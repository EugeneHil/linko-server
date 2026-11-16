# Vendored: OpenSSL applink

`applink.c` is vendored verbatim from the OpenSSL sources
(`ms/applink.c`, OpenSSL master as of 2026-11-17; the file has been
stable since 2004). License: Apache-2.0 (OpenSSL project, see the header
in the file). Not modified.

## Why it is vendored

The vcpkg Windows OpenSSL is built with uplink support. Any process that
calls OpenSSL functions taking a `FILE*` — `SSL_CTX_use_certificate_chain_file`,
`SSL_CTX_use_PrivateKey_file`, `BIO_new_file`, … — must itself export the
`OPENSSL_Applink` table, or OpenSSL aborts the process with:

```
OPENSSL_Uplink(00007FFC3029F488,08): no OPENSSL_Applink
```

MSVC test and `linko-server` executables compile this file into themselves
(wired in the root and `tests/CMakeLists.txt` under `if(MSVC)`), which
exports the table. The table bridges OpenSSL's uplink calls back into the
executable's own C runtime, so `FILE*` handles stay inside the process.

On macOS (Homebrew OpenSSL) none of this applies; the file is compiled
nowhere. Only MSVC builds need it — first observed as the mass failure of
every TLS-touching suite in the LNK-25 Windows CI job.
