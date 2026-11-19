# LockBox

A PIN-protected, **device-bound** vault app for the [Flipper Zero](https://flipperzero.one/).
LockBox encrypts your saved **NFC**, **RFID** and **SubGHz** files — plus free-form
**Secure Notes** — so a stolen SD card or a copied file is useless on any other device.

> Author: **LeviXX**

## Features

- **Encrypt NFC / RFID / SubGHz** — pick a file; it is encrypted into the vault
  (`.lbx`) and removed from its original app.
- **My Vault** — list stored items, decrypt (restore) them back to their app, or delete.
- **Secure Notes** — store text/passwords, encrypted the same way.
- **Direction-button PIN** — Up/Down/Left/Right/Back sequence, like the Momentum lock code.
- **Brute-force lockout** — escalating timeout after wrong PINs (30s → 60s → 120s →
  5 min → 10 min), persisted across restarts.
- **Change PIN** with optional re-encryption of every stored item under the new key.

## Security model

- The encryption key is **never stored**. It is derived from **this Flipper's unique
  hardware serial (UID) + your PIN**, run through a slow SHA-256 KDF (8000 rounds)
  with a random per-file salt.
- Cipher: SHA-256 keystream (hash-CTR) — a real cryptographic primitive, not plain XOR.
- Because the key needs **both** the device serial (not on the SD card) **and** the PIN,
  a copied `.lbx` file cannot be decrypted off this device or without the PIN.
- The PIN itself is stored only as a hash (`pin.dat`); changing it re-keys the vault.

> Decrypt your cards and notes **before** changing the PIN if you skip re-encryption.

## Build & install

Built with [ufbt](https://pypi.org/project/ufbt/) (micro Flipper Build Tool):

```bash
pip install ufbt
ufbt            # build -> dist/lockbox.fap
ufbt launch     # build, install to the connected Flipper, and launch
```

The app appears on the device under **Apps → Tools → LockBox**.

## Files

| Path | Purpose |
|------|---------|
| `application.fam` | App manifest (id, name, icon, metadata) |
| `lockbox.c` | Full app source (SHA-256, PIN view, vault, notes, lockout) |
| `lockbox_icon.png` | 10×10 app icon |
| `images/` | Icon assets |

## License

MIT — see [LICENSE](LICENSE).
