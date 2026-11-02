Test-only signing identity for `src/p12.rs` and `src/sign.rs` tests. The key is not secret and
signs nothing real: a self-signed RSA 2048 certificate shaped like an Apple Development one.

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 36500 \
  -subj "/UID=TESTTEAM01/CN=Apple Development: rios test (TESTTEAM01)/OU=TESTTEAM01/O=rios test/C=US"
openssl x509 -in cert.pem -outform DER -out cert.der
# OpenSSL 3+ defaults: PBES2/PBKDF2-SHA256/AES-256-CBC, SHA-256 MAC
openssl pkcs12 -export -inkey key.pem -in cert.pem -passout pass:test -out pbes2-aes256.p12
openssl pkcs12 -export -inkey key.pem -in cert.pem -passout pass:test \
  -keypbe DES-EDE3-CBC -certpbe DES-EDE3-CBC -out pbes2-3des.p12
openssl pkcs12 -export -inkey key.pem -in cert.pem -passout pass:test \
  -keypbe AES-128-CBC -certpbe AES-128-CBC -nomac -out nomac-aes128.p12
openssl pkcs12 -export -inkey key.pem -in cert.pem -passout pass: -out empty-password.p12
# LibreSSL (macOS /usr/bin/openssl) defaults, like Keychain exports: 3DES key, RC2-40 certs, SHA-1 MAC
/usr/bin/openssl pkcs12 -export -inkey key.pem -in cert.pem -passout pass:test -out legacy-3des-rc2.p12
```
