# PyCryptX

The coninuation of [PyCrypt](https://github.com/xannythepleb/pycrypt), my rudimentary Python encryption program, now with Curve25519 based public key cryptography!

Like the original, this is just a hobby project. It is absolutely unaudited and has only been tested on my own machine. If you notice any bugs or potential vulnerabilities, please open an issue or a PR if you're a dev!

PyCryptX uses X25519 for secret key exchange to setup asymemetic encryption, HKDF with BLAKE2b for 64 byte key derivation, ChaCha20 for asyemmetic encryption, and in a future update will soon activate Ed25519 for signatures (Ed25519 keys already generated).

This software is loosely modelled on PGP and does not offer forward secrecy, but in the future may enable it.

It only uses the Python 3 `cryptography` library and does not have any other dependencies.

Just to make sure this is clear: **this is an unaudited hobby project and should not be used for security essential production environments!**

You should also **back up any file you use this on!**

## How to use

1. Open in its own directory
2. It's helpful to put any files you plan to encrypt or decrypt inside the same directory as the scripts
3. Run `PyCryptX-keygen.py`
4. Once your keys are generated in a second, run `PyCryptoX.py` and choose if you want to encrypt or decrypt
5. You can share the X25519 and Ed25519 public keys with anyone. Keep the private keys safe.
6. You can generate new keys at any time by running the key generation key script again. But this will overwrite your current ones. If you may need them, back them up in another directory first.
7. To restore old keys, put them in the same directory as the scripts. Don't change the names of the private keys.

Report any bugs.

Enjoy!
