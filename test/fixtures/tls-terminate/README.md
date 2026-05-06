# tlsTerminate test fixture CA

`ca.crt` / `ca.key` are a **test-only** self-signed CA used by
`test/sandbox/mitm-ca.test.ts`. The private key is intentionally committed —
it is never used outside the test suite and must never be trusted by anything.

Generated with:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
  -keyout ca.key -out ca.crt -days 36500 \
  -subj '/CN=srt-test-ca DO NOT TRUST/O=sandbox-runtime test fixture'
```

Regenerate with the same command if the files are ever lost or need rotating.
