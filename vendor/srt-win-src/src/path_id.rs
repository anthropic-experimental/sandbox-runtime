//! Path canonicalization and file-identity (`FILE_ID_INFO`)
//! helpers — the "which file is this, exactly" layer that
//! `state_db.rs` keys on and `main.rs` validates with. Nothing here
//! touches ACL/ACE/SD types; the ACL machinery lives in
//! [`crate::acl`].

use anyhow::{Context, Result, bail};
use std::mem::size_of;
use windows::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_DIRECTORY, FILE_FLAG_BACKUP_SEMANTICS, FILE_NAME_NORMALIZED,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, GETFINALPATHNAMEBYHANDLE_FLAGS,
    GetFinalPathNameByHandleW, OPEN_EXISTING, VOLUME_NAME_DOS,
};

use crate::util::{OwnedHandle, pcwstr, wstr};

/// True iff `decoded` round-trips back to `original` via
/// `encode_utf16` — i.e., `from_utf16_lossy(original)` was
/// lossless (no unpaired-surrogate substitution).
#[inline]
fn utf16_roundtrips(original: &[u16], decoded: &str) -> bool {
    decoded.encode_utf16().eq(original.iter().copied())
}

/// Typed [`canonicalize_path`] error. The hard-error vs
/// soft-skip decision in `main.rs` matches on the variant rather
/// than a substring of the formatted message, so a wording change
/// here cannot silently downgrade a glob to a skip.
#[derive(Debug)]
pub enum CanonError {
    /// Input contains `*` or `?` (outside the `\\?\` prefix).
    /// Always a config bug — never transient.
    Glob,
    /// Open / final-path / attribute read failed (covers
    /// `ERROR_FILE_NOT_FOUND`, unpaired-surrogate canonical paths,
    /// and any other Win32 error).
    Other(anyhow::Error),
}

impl std::fmt::Display for CanonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Glob => write!(
                f,
                "Windows fs deny requires explicit file or directory \
                 paths; got glob"
            ),
            Self::Other(e) => write!(f, "{e:#}"),
        }
    }
}
impl std::error::Error for CanonError {}

/// Resolve `path` to its kernel-canonical form via
/// `GetFinalPathNameByHandleW` (handles symlinks, junctions, 8.3
/// short names, drive-letter case). Returns the `\\?\`-prefixed
/// path and whether it's a directory.
///
/// `state_db.rs` uses the canonical path as the DB key so a stamp
/// via two equivalent paths (e.g. `C:\PROGRA~1\…` and
/// `C:\Program Files\…`) refcounts correctly.
///
/// Returns [`CanonError::Other`] for any open/resolve failure,
/// including a canonical path that is not UTF-8-representable
/// (unpaired surrogates) — fail closed rather than round-trip a
/// U+FFFD-substituted string into the wrong filesystem object.
pub fn canonicalize_path(path: &str) -> Result<(String, bool), CanonError> {
    // Glob check on the INPUT, ignoring the `\\?\` extended-path
    // prefix (its `?` is not a wildcard). Without the strip,
    // canonicalize_path would reject its OWN output (which always
    // carries the prefix).
    let glob_in = path.strip_prefix(r"\\?\").unwrap_or(path);
    if glob_in.contains('*') || glob_in.contains('?') {
        return Err(CanonError::Glob);
    }
    (|| -> Result<(String, bool)> {
        // Open without requesting any data access so we don't
        // need read permission on the target.
        // `BACKUP_SEMANTICS` lets directories open too.
        let h = open_for_metadata(path)
            .with_context(|| format!("open '{path}' for canonicalization"))?;

        let buf = final_path_from_handle(h.raw())
            .with_context(|| format!("GetFinalPathNameByHandleW('{path}')"))?;
        let canonical = String::from_utf16_lossy(&buf);
        if !utf16_roundtrips(&buf, &canonical) {
            bail!(
                "canonical path for '{path}' is not representable as \
                 UTF-8 (contains unpaired surrogates); not supported"
            );
        }

        // Directory check on the OPEN HANDLE (not a path
        // re-resolve): the handle was opened without
        // `FILE_FLAG_OPEN_REPARSE_POINT`, so a symlink-to-dir was
        // already followed and `h` is the directory itself.
        use windows::Win32::Storage::FileSystem::{
            FILE_BASIC_INFO, FileBasicInfo, GetFileInformationByHandleEx,
        };
        let mut info = FILE_BASIC_INFO::default();
        unsafe {
            GetFileInformationByHandleEx(
                h.raw(),
                FileBasicInfo,
                (&mut info as *mut FILE_BASIC_INFO).cast(),
                size_of::<FILE_BASIC_INFO>() as u32,
            )
        }
        .with_context(|| format!("GetFileInformationByHandleEx(FileBasicInfo) '{path}'"))?;
        let is_dir = info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
        Ok((canonical, is_dir))
    })()
    .map_err(CanonError::Other)
}

/// Open `path` with no data access (`dwDesiredAccess = 0`), full
/// sharing, `BACKUP_SEMANTICS` (so directories open), `OPEN_EXISTING`.
/// Shared by every metadata-query helper so a future change to the
/// open flags (e.g. `FILE_FLAG_OPEN_REPARSE_POINT`) lands once.
fn open_for_metadata(path: &str) -> Result<OwnedHandle> {
    let w = wstr(path);
    let h = unsafe {
        CreateFileW(
            pcwstr(&w),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }?;
    if h == INVALID_HANDLE_VALUE {
        bail!("CreateFileW('{path}'): INVALID_HANDLE_VALUE");
    }
    Ok(OwnedHandle(h))
}

/// `GetFinalPathNameByHandleW` two-call sizing pattern. Returns the
/// raw UTF-16 buffer (no NUL); caller decodes and round-trip-checks.
fn final_path_from_handle(h: HANDLE) -> Result<Vec<u16>> {
    let flags = GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0);
    let need = unsafe { GetFinalPathNameByHandleW(h, &mut [], flags) };
    if need == 0 {
        bail!("sizing: {}", std::io::Error::last_os_error());
    }
    let mut buf = vec![0u16; need as usize + 1];
    let n = unsafe { GetFinalPathNameByHandleW(h, &mut buf, flags) };
    if n == 0 || n as usize >= buf.len() {
        // n >= buf.len() means "buffer too small" (a concurrent
        // rename grew the path between the size probe and the
        // data call). We bail rather than retry — narrow window,
        // and the caller can re-stamp.
        bail!("{}", std::io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(buf)
}

/// Immediate parent of a `\\?\…` canonical path, as a string.
/// Returns `None` when there is no targetable parent (the path is
/// a root, or its immediate parent is a root — touching the
/// volume root's DACL is out of scope for the parent
/// `DenyFdc` ACE).
pub fn canonical_parent_of(canonical_path: &str) -> Option<String> {
    std::path::Path::new(canonical_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty() && p.parent().is_some())
        .map(|p| p.display().to_string())
}

// ─── File identity (FILE_ID_INFO) ───────────────────────────────────

/// A file's stable identity on a volume — the
/// `(VolumeSerialNumber, FileId128)` pair from `FILE_ID_INFO`. On
/// NTFS this is the MFT record identity, so it survives rename
/// and lets us both VALIDATE at restore time (the path still
/// resolves to the same file we stamped) and LOCATE a relocated
/// file for reporting. Stored as a 24-byte blob (8 + 16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId {
    pub volume_serial: u64,
    pub id128: [u8; 16],
}

impl FileId {
    pub fn as_bytes(&self) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[..8].copy_from_slice(&self.volume_serial.to_le_bytes());
        out[8..].copy_from_slice(&self.id128);
        out
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 24 {
            bail!("FileId::from_bytes: expected 24 bytes, got {}", b.len());
        }
        let mut vs = [0u8; 8];
        vs.copy_from_slice(&b[..8]);
        let mut id = [0u8; 16];
        id.copy_from_slice(&b[8..]);
        Ok(Self {
            volume_serial: u64::from_le_bytes(vs),
            id128: id,
        })
    }
}

/// `FILE_ID_INFO` of an already-open handle.
fn file_id_from_handle(h: HANDLE) -> Result<FileId> {
    use windows::Win32::Storage::FileSystem::{
        FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
    };
    let mut info = FILE_ID_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            h,
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .context("GetFileInformationByHandleEx(FileIdInfo)")?;
    Ok(FileId {
        volume_serial: info.VolumeSerialNumber,
        id128: info.FileId.Identifier,
    })
}

/// `FILE_ID_INFO` of `canonical_path`. Opens with no data access
/// (identity query only), so a DENY-ACE on the file does not
/// interfere — the broker is the real user, not the deny trustee.
pub fn capture_file_id(canonical_path: &str) -> Result<FileId> {
    let h = open_for_metadata(canonical_path)
        .with_context(|| format!("open '{canonical_path}' for file_id"))?;
    file_id_from_handle(h.raw()).with_context(|| format!("file_id '{canonical_path}'"))
}

/// `(file_id, NumberOfLinks, is_dir)` from ONE metadata open.
/// `links > 1` on a non-directory means an alternate hardlink
/// name exists; the additive-ACE refcount in `state_db` is
/// PATH-keyed, so releasing one alias would strip the SHARED
/// DACL while another alias's holder still expects it denied.
/// Directory `NumberOfLinks` counts subdirs (NTFS has no dir
/// hardlinks), so callers gate the check on `!is_dir`.
pub fn capture_id_and_links(canonical_path: &str) -> Result<(FileId, u32, bool)> {
    use windows::Win32::Storage::FileSystem::{
        FILE_STANDARD_INFO, FileStandardInfo, GetFileInformationByHandleEx,
    };
    let h = open_for_metadata(canonical_path)
        .with_context(|| format!("open '{canonical_path}' for file_id+links"))?;
    let id = file_id_from_handle(h.raw()).with_context(|| format!("file_id '{canonical_path}'"))?;
    let mut std_info = FILE_STANDARD_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            h.raw(),
            FileStandardInfo,
            (&mut std_info as *mut FILE_STANDARD_INFO).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    }
    .with_context(|| {
        format!(
            "GetFileInformationByHandleEx(FileStandardInfo) \
             '{canonical_path}'"
        )
    })?;
    Ok((id, std_info.NumberOfLinks, std_info.Directory))
}

/// Best-effort: locate the CURRENT path of a file by its captured
/// `(volume_serial, file_id)`. Opens the volume root (`\\?\X:\`),
/// `OpenFileById` with an `ExtendedFileId` descriptor, then
/// `GetFinalPathNameByHandleW`. Returns `None` if the file was
/// deleted or the open fails for any reason. Used ONLY for
/// reporting `movedTo` — restore is path-anchored and never
/// relocates by inode (chasing the file by ID to remove its stamp
/// would re-expose a relocated secret).
pub fn locate_by_file_id(file_id: &FileId) -> Option<String> {
    use windows::Win32::Storage::FileSystem::{
        ExtendedFileIdType, FILE_ID_128, FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, OpenFileById,
    };
    // Open the volume root the file lived on. We need a handle ON
    // the volume to anchor OpenFileById; the captured volume
    // serial doesn't directly map to a drive letter, so try each
    // mounted local drive and match the serial — keeping the
    // locate volume-keyed (a moved file may not be on the drive
    // its canonical_path was recorded under).
    for drive in b'A'..=b'Z' {
        let root = format!(r"\\?\{}:\", drive as char);
        let vh = match open_for_metadata(&root) {
            Ok(h) => h,
            Err(_) => continue,
        };
        // Match the volume by reading FILE_ID_INFO of the root.
        match file_id_from_handle(vh.raw()) {
            Ok(id) if id.volume_serial == file_id.volume_serial => {}
            _ => continue,
        }
        let desc = FILE_ID_DESCRIPTOR {
            dwSize: std::mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
            Type: ExtendedFileIdType,
            Anonymous: FILE_ID_DESCRIPTOR_0 {
                ExtendedFileId: FILE_ID_128 {
                    Identifier: file_id.id128,
                },
            },
        };
        // dwDesiredAccess = 0: GetFinalPathNameByHandleW needs only
        // a valid handle, not read-data, so a relocated file whose
        // DACL no longer grants the broker read still resolves.
        let fh = match unsafe {
            OpenFileById(
                vh.raw(),
                &desc,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                FILE_FLAG_BACKUP_SEMANTICS,
            )
        } {
            Ok(h) => OwnedHandle(h),
            Err(_) => return None,
        };
        let buf = final_path_from_handle(fh.raw()).ok()?;
        let s = String::from_utf16_lossy(&buf);
        return utf16_roundtrips(&buf, &s).then_some(s);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_rejects_globs() {
        for p in ["C:\\foo\\*.txt", "C:\\foo\\bar?.txt"] {
            assert!(matches!(canonicalize_path(p), Err(CanonError::Glob)), "{p}");
        }
        assert!(matches!(
            canonicalize_path(r"C:\srt-win-no-such-path"),
            Err(CanonError::Other(_))
        ));
    }

    #[test]
    fn canonicalize_round_trip_self() {
        // The test binary's own path is a real file we definitely
        // can open.
        let exe = std::env::current_exe().unwrap();
        let (canon, is_dir) = canonicalize_path(&exe.display().to_string()).unwrap();
        assert!(canon.starts_with(r"\\?\"), "got {canon}");
        assert!(!is_dir);
        // Round-trip: canonicalizing the canonical path is a no-op.
        let (again, _) = canonicalize_path(&canon).unwrap();
        assert_eq!(canon, again);
    }

    /// The parent of a file directly under a drive root IS the
    /// volume root. Touching the volume root's DACL (even with an
    /// additive `DenyFdc` ACE) is out of scope — so
    /// `canonical_parent_of` must return `None` for a top-level
    /// child. Rust's `Path::parent()` returns the root (not
    /// `None`) in this case, so the helper has to recognize and
    /// reject it.
    #[test]
    fn parent_at_volume_root_is_not_stampable() {
        for p in [r"\\?\C:\foo.txt", r"\\?\C:\ProgramData", r"\\?\D:\x"] {
            assert_eq!(
                canonical_parent_of(p),
                None,
                "would stamp the volume root for top-level child {p:?}: \
                 got {:?}",
                canonical_parent_of(p),
            );
        }
        // Anchors (already pass today, must keep passing):
        // the root itself has no parent; a nested path's parent
        // is the immediate directory.
        assert_eq!(canonical_parent_of(r"\\?\C:\"), None);
        assert_eq!(
            canonical_parent_of(r"\\?\C:\a\b").as_deref(),
            Some(r"\\?\C:\a"),
        );
    }

    #[test]
    fn lossy_canonical_path_detected() {
        // Lone high surrogate → from_utf16_lossy substitutes
        // U+FFFD, so the round-trip check must reject it.
        let bad = [0x0041, 0xD800, 0x0042];
        assert!(!utf16_roundtrips(&bad, &String::from_utf16_lossy(&bad)));
        // A valid surrogate PAIR (U+1F600 = D83D DE00) and plain
        // ASCII both round-trip.
        let pair = [0x0041, 0xD83D, 0xDE00, 0x0042];
        assert!(utf16_roundtrips(&pair, &String::from_utf16_lossy(&pair)));
        let ok = [0x0041, 0x0042];
        assert!(utf16_roundtrips(&ok, &String::from_utf16_lossy(&ok)));
    }
}
