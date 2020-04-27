## Usage examples and supported subcommands
### Generate a key-pair
The following command generates a **private key**:
```
gosop generate-key "Alice <alice@example.com>" > private-key.sec
```
Note that, as per the OpenPGP specification, this private key also
contains public key material. You can extract the **public key** (also referred
to as _certificate_) safely as
follows:
```
gosop extract-cert < private-key.sec > public-key.pgp
```
This outputs PGP armored strings by default
```
$ head -n1 private-key.sec
-----BEGIN PGP PRIVATE KEY BLOCK-----
$ head -n1 public-key.pgp
-----BEGIN PGP PUBLIC KEY BLOCK-----
```
but you may use binary format providing the `--no-armor` flag to the above
commands.

### Encrypt/decrypt
##### Using a passphrase
```
gosop encrypt --with-password="strong_passphrase" < input_file > encrypted_file
gosop decrypt --with-password="strong_passphrase" < encrypted_file > decrypted_file
```
##### Using PGP keys

```
gosop encrypt public-key.pgp < file_to_encrypt > encrypted_file
gosop decrypt private-key.sec < encrypted_file > decrypted_file
```

For advanced modes and available flags, run `gosop help encrypt`, `gosop help
decrypt`.

### Sign/Verify

```
gosop sign private-key.sec < file_to_sign > signature.asc
gosop verify signature public-key.asc < signature.asc
```
You need to inspect the exit status and output of `verify` to check if the
signature is valid.

### Armor/Dearmor
Any PGP armored string, you can convert it to/from binary. `gosop` will
automatically detect the type from the underlying packets, and set the correct
headers (`SIGNATURE`, `MESSAGE`, etc).

```
gosop dearmor < public-key.asc > public-key-binary
```
