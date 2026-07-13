//! Install-time write of the MITM CA into the **sandbox user's**
//! `CurrentUser\Root` store.
//!
//! Writes the serialized cert element straight to
//! `HKEY_USERS\<own-SID>\Software\Microsoft\SystemCertificates\Root\Certificates\<thumb>`
//! (value `Blob`, `REG_BINARY`). schannel reads that key live, and a
//! raw registry write **bypasses crypt32's protected-root UI hook
//! entirely** — the dialog that any crypt32 store-API add to
//! `CurrentUser\Root` (including the
//! `CERT_STORE_PROV_SYSTEM_REGISTRY` provider, which we tried first)
//! pops. On the runner's non-interactive desktop that dialog has
//! nobody to dismiss it, so the runner hangs; the registry write is
//! the only verified-silent path.
//!
//! The write addresses `HKEY_USERS\<SID>` **explicitly**, not the
//! `HKEY_CURRENT_USER` predefined key. Addressing the hive by SID
//! under `HKEY_USERS` removes the predefined-key cache from the
//! equation: the profile is loaded (`LOGON_WITH_PROFILE`), so
//! `HKU\<SID>` is mounted.
//!
//! **Platform caveat — Windows Server 2022:** on the GHA Server 2022
//! runner, the restricted-token child created via
//! `CreateProcessAsUserW` was observed to resolve `CurrentUser` (both
//! `HKCU` and crypt32's logical `CurrentUser` store) to the **host
//! process's** hive, not the sandbox user's — despite the token's user
//! SID being `srt-sandbox` and `HKU\<srt-sandbox-SID>` being mounted
//! and containing the runner's write. On Windows 11 desktop the same
//! sequence resolves to the sandbox user's hive and the cert is
//! visible (verified by direct probe). The `HKU\<SID>` write here is
//! correct on both; the env-var CA-trust path
//! (`NODE_EXTRA_CA_CERTS`/`SSL_CERT_FILE`/…) is the cross-platform
//! mechanism the broker also sets. Follow-up: investigate Server-SKU
//! HKCU resolution under restricted tokens.
//!
//! `Blob` is the **serialized cert element**
//! (`CertSerializeCertificateStoreElement` — DER plus crypt32's
//! property TLVs), NOT raw DER; raw DER under that value name is
//! ignored by schannel (`SEC_E_UNTRUSTED_ROOT`).
//!
//! **Lifecycle = sandbox-user lifecycle.** Called once from `srt-win
//! user trust-ca` via a one-shot
//! `CreateProcessWithLogonW(srt-sandbox, "srt-win runner")` with
//! [`crate::runner::RunnerCmd::InstallCa`]. The cert lives in the
//! **sandbox user's** hive — isolated from the real user — and is
//! removed when `srt-win uninstall` calls `DeleteProfileW`. `srt-win
//! exec` does NOT touch this module.

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use windows::Win32::Security::Cryptography::{
    CRYPT_STRING_ANY, CRYPT_STRING_BASE64HEADER, CertCreateCertificateContext,
    CertFreeCertificateContext, CertSerializeCertificateStoreElement, CryptBinaryToStringA,
    CryptHashCertificate2, CryptStringToBinaryA, X509_ASN_ENCODING,
};
use windows::Win32::System::Registry::{HKEY_USERS, REG_BINARY};
use windows::core::{PCWSTR, PSTR};

use crate::sid;
use crate::util::{reg_set_value, wstr};

const ROOT_CERTS_REL: &str = "Software\\Microsoft\\SystemCertificates\\Root\\Certificates";

/// DER-encoded X.509 certificate. Newtype so the cert bytes can't be
/// confused with the DPAPI ciphertext, the serialized store element,
/// or any other `Vec<u8>` that flows through install/state-DB code.
/// `serde(transparent)` keeps the [`crate::runner::RunnerCmd`] wire
/// shape unchanged; `ToSql`/`FromSql` map straight to a SQLite BLOB.
///
/// **Invariant:** the bytes are the **canonical** DER span — exactly
/// `pbCertEncoded[..cbCertEncoded]` as crypt32 parsed it, with no
/// leading or trailing slack. [`from_pem_or_der`] enforces this; the
/// serde / SQLite round-trip paths only carry values that were
/// constructed that way. So [`thumb`] and [`install_root_ca`] (which
/// re-parses for serialization) always agree.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CertDer(Vec<u8>);

impl CertDer {
    /// Decode `bytes` as a single DER-encoded X.509 certificate and
    /// **canonicalize** to crypt32's parsed-exact span.
    ///
    /// Input that already starts with a DER `SEQUENCE` tag (`0x30`)
    /// and is not a `-----BEGIN` text block is treated as binary;
    /// otherwise `CryptStringToBinaryA(CRYPT_STRING_ANY)` decodes
    /// PEM (with headers), bare base64, or hex. Either way the
    /// decoded bytes are then parsed via
    /// `CertCreateCertificateContext` and the result is
    /// `pbCertEncoded[..cbCertEncoded]` — so trailing bytes after
    /// the outer SEQUENCE (which crypt32 tolerates on parse) are
    /// dropped, and an input that doesn't parse as X.509 is rejected
    /// here rather than later.
    pub fn from_pem_or_der(bytes: &[u8]) -> Result<Self> {
        // Short-circuit BEFORE `CryptStringToBinaryA`: arbitrary
        // binary is not a valid `CRYPT_STRING_ANY` input (it expects
        // text), so recognise DER by its leading tag and feed it to
        // the canonicalizer directly.
        if bytes.first() == Some(&0x30)
            && std::str::from_utf8(bytes)
                .map(|s| !s.contains("-----BEGIN"))
                .unwrap_or(true)
        {
            return Ok(Self(parse_cert_span(bytes)?));
        }
        let mut len: u32 = 0;
        unsafe { CryptStringToBinaryA(bytes, CRYPT_STRING_ANY, None, &mut len, None, None) }
            .context("CryptStringToBinaryA (sizing)")?;
        let mut out = vec![0u8; len as usize];
        unsafe {
            CryptStringToBinaryA(
                bytes,
                CRYPT_STRING_ANY,
                Some(out.as_mut_ptr()),
                &mut len,
                None,
                None,
            )
        }
        .context("CryptStringToBinaryA")?;
        out.truncate(len as usize);
        if out.is_empty() {
            return Err(anyhow!("PEM/base64 input decoded to empty"));
        }
        Ok(Self(parse_cert_span(&out)?))
    }

    /// Test-only raw constructor — bypasses the X.509 parse so unit
    /// tests of the wire/serde layer don't need a real cert.
    #[cfg(test)]
    pub(crate) fn raw(v: Vec<u8>) -> Self {
        Self(v)
    }

    /// SHA-1 thumbprint as uppercase hex
    /// (`Cert:\…\Thumbprint`-compatible). Uses crypt32's
    /// `CryptHashCertificate2` so the value matches
    /// `CERT_HASH_PROP_ID` exactly.
    pub fn thumb(&self) -> Result<String> {
        let mut h = [0u8; 20];
        let mut len = h.len() as u32;
        let alg = wstr("SHA1");
        unsafe {
            CryptHashCertificate2(
                PCWSTR(alg.as_ptr()),
                0,
                None,
                Some(&self.0),
                Some(h.as_mut_ptr()),
                &mut len,
            )
        }
        .context("CryptHashCertificate2(SHA1)")?;
        let mut s = String::with_capacity(40);
        for b in h {
            s.push_str(&format!("{b:02X}"));
        }
        Ok(s)
    }

    /// PEM-encode (`-----BEGIN CERTIFICATE-----` headers, 64-col
    /// base64, CRLF). Used by `srt-win user status` to surface the
    /// install-time CA in a form the host can write straight to a
    /// `.crt` file for the env-var trust layer.
    pub fn to_pem(&self) -> Result<String> {
        let mut len: u32 = 0;
        let r = unsafe { CryptBinaryToStringA(&self.0, CRYPT_STRING_BASE64HEADER, None, &mut len) };
        if !r.as_bool() || len == 0 {
            return Err(anyhow!(
                "CryptBinaryToStringA (sizing): {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut buf = vec![0u8; len as usize];
        let r = unsafe {
            CryptBinaryToStringA(
                &self.0,
                CRYPT_STRING_BASE64HEADER,
                Some(PSTR(buf.as_mut_ptr())),
                &mut len,
            )
        };
        if !r.as_bool() {
            return Err(anyhow!(
                "CryptBinaryToStringA: {}",
                std::io::Error::last_os_error()
            ));
        }
        // `len` excludes the trailing NUL on the fill call.
        buf.truncate(len as usize);
        String::from_utf8(buf).context("CryptBinaryToStringA returned non-UTF-8")
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Parse `bytes` via `CertCreateCertificateContext` and return a
/// copy of `pbCertEncoded[..cbCertEncoded]` — crypt32's parsed-exact
/// view of the cert. Tolerates trailing bytes after the outer
/// SEQUENCE on input; the returned span never has them. Errors if
/// `bytes` is not a parseable X.509 cert.
fn parse_cert_span(bytes: &[u8]) -> Result<Vec<u8>> {
    let ctx = unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, bytes) };
    if ctx.is_null() {
        return Err(anyhow!(
            "CertCreateCertificateContext: {} (input is not a \
             parseable X.509 certificate)",
            std::io::Error::last_os_error()
        ));
    }
    let span =
        unsafe { std::slice::from_raw_parts((*ctx).pbCertEncoded, (*ctx).cbCertEncoded as usize) }
            .to_vec();
    unsafe {
        let _ = CertFreeCertificateContext(Some(ctx));
    }
    Ok(span)
}

impl rusqlite::ToSql for CertDer {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(rusqlite::types::ToSqlOutput::from(self.0.as_slice()))
    }
}

impl rusqlite::types::FromSql for CertDer {
    fn column_result(v: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        v.as_blob().map(|b| Self(b.to_vec()))
    }
}

/// Install `der` into the calling user's `CurrentUser\Root` by
/// writing the serialized cert element to
/// `HKEY_USERS\<own-SID>\…\Root\Certificates\<thumb>` ∖ `Blob`.
/// Idempotent (overwrite). Persistent until the calling user's
/// profile is deleted.
///
/// Returns the cert's SHA-1 thumbprint (uppercase hex —
/// `Cert:\…\Thumbprint`-compatible).
pub fn install_root_ca(der: &CertDer) -> Result<String> {
    // Parse the DER into a transient CERT_CONTEXT (no store
    // association) for `CertSerializeCertificateStoreElement`. The
    // [`CertDer`] invariant guarantees `der.as_bytes()` is already
    // the canonical `pbCertEncoded` span, so `der.thumb()` and the
    // serialized element agree without re-reading the context's
    // span here.
    let ctx = unsafe { CertCreateCertificateContext(X509_ASN_ENCODING, der.as_bytes()) };
    if ctx.is_null() {
        return Err(anyhow!(
            "CertCreateCertificateContext: {}",
            std::io::Error::last_os_error()
        ));
    }
    let r_thumb = der.thumb();

    // Serialized store element (two-call size-then-fill).
    let mut blob_len: u32 = 0;
    let r_blob = unsafe { CertSerializeCertificateStoreElement(ctx, 0, None, &mut blob_len) }
        .and_then(|_| {
            let mut buf = vec![0u8; blob_len as usize];
            unsafe {
                CertSerializeCertificateStoreElement(ctx, 0, Some(buf.as_mut_ptr()), &mut blob_len)
            }
            .map(|_| buf)
        });
    unsafe {
        let _ = CertFreeCertificateContext(Some(ctx));
    }
    let thumb = r_thumb?;
    let blob = r_blob.context("CertSerializeCertificateStoreElement")?;

    // HKU\<own-SID>\…\Root\Certificates\<THUMB> — `RegCreateKeyExW`
    // creates intermediate keys, so a fresh sandbox-user hive
    // (no prior Root entries) is fine. See module doc for why
    // `HKEY_USERS\<SID>` and not `HKEY_CURRENT_USER`.
    let user_sid = sid::current_user_sid().context("cert_store: own user SID")?;
    let sub = format!("{user_sid}\\{ROOT_CERTS_REL}\\{thumb}");
    reg_set_value(HKEY_USERS, &sub, "Blob", REG_BINARY, &blob)
        .with_context(|| format!("write HKU\\{sub}"))?;
    Ok(thumb)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PEM-encoded test fixture (the same `srt-test-ca` the TS-side
    /// tls-terminate tests use). `from_pem_or_der` parses it to a
    /// real `CERT_CONTEXT`, so the canonicalization step is
    /// exercised end-to-end.
    const CA_PEM: &[u8] = include_bytes!("../../../test/fixtures/tls-terminate/ca.crt");

    #[test]
    fn pem_roundtrip_is_canonical() {
        let c = CertDer::from_pem_or_der(CA_PEM).unwrap();
        // Re-encode → re-decode is byte-identical.
        let pem = c.to_pem().unwrap();
        assert!(pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(
            CertDer::from_pem_or_der(pem.as_bytes()).unwrap().as_bytes(),
            c.as_bytes()
        );
        // 40-hex-char SHA-1 thumb.
        assert_eq!(c.thumb().unwrap().len(), 40);
    }

    #[test]
    fn der_with_trailing_bytes_canonicalizes() {
        let canon = CertDer::from_pem_or_der(CA_PEM).unwrap();
        // DER input + junk past the outer SEQUENCE → same canonical
        // bytes, same thumb.
        let mut dirty = canon.as_bytes().to_vec();
        dirty.extend_from_slice(b"\x00trailing junk");
        let reparsed = CertDer::from_pem_or_der(&dirty).unwrap();
        assert_eq!(reparsed.as_bytes(), canon.as_bytes());
        assert_eq!(reparsed.thumb().unwrap(), canon.thumb().unwrap());
    }

    #[test]
    fn rejects_non_x509() {
        // SEQUENCE-tagged but not a cert → CertCreateCertificateContext
        // fails and so does the constructor.
        assert!(CertDer::from_pem_or_der(b"\x30\x03\x02\x01\x05").is_err());
        // PEM-wrapped non-cert payload → same.
        let pem = b"-----BEGIN CERTIFICATE-----\r\naGVsbG8=\r\n-----END CERTIFICATE-----\r\n";
        assert!(CertDer::from_pem_or_der(pem).is_err());
    }
}
