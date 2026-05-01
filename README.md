# C++ Password Manager & Encrypter

A native Windows GUI application for securely storing and managing passwords. Built with C++ using the Win32 API and a fully custom cryptography implementation — no third-party libraries.

---

## Background

This project was created in April 2025 as part of **Cryptography 445** at **East Texas A&M University**. The goal was to apply and expand on course concepts — specifically SHA-256 hashing and symmetric encryption — by building a real, functional application from scratch.

---

## Features

- **Encrypted vault** — all credentials are stored in an AES-256-CBC encrypted binary file on disk
- **Master password protection** — the vault is locked behind a master password; nothing can be read without it
- **Per-entry password masking** — passwords are hidden by default and can be revealed individually
- **Clipboard copy** — copy any password to the clipboard without ever displaying it
- **Random password generator** — generates a secure 16-character password using the Windows cryptographic RNG
- **Add / Edit / Delete entries** — each entry stores a title, username, password, URL, and notes
- **Change master password** — re-derives the encryption key and re-encrypts the entire vault
- **No external dependencies** — crypto primitives are implemented entirely in C++; the only libraries used are the Windows system DLLs

---

## Cryptography

The cryptographic layer was implemented from scratch as the core learning objective of this project.

### SHA-256
SHA-256 is used as the underlying hash function throughout the application. It is implemented in pure C++ following the FIPS 180-4 specification, including the full message schedule, compression function, and padding scheme.

### HMAC-SHA256
HMAC (Hash-based Message Authentication Code) wraps SHA-256 to produce a keyed hash. This is used as the building block for key derivation.

### PBKDF2-HMAC-SHA256
Password-Based Key Derivation Function 2 stretches the master password into a 256-bit AES key using 100,000 iterations and a random 32-byte salt. This makes brute-force and dictionary attacks computationally expensive. A separate PBKDF2 call (with a different salt context) is used to derive a verification hash so the application can confirm the correct password was entered without storing the password itself.

### AES-256-CBC
The derived key is used with AES-256 in CBC (Cipher Block Chaining) mode to encrypt all vault data. The AES implementation includes the full key schedule (14 rounds for 256-bit keys), SubBytes, ShiftRows, MixColumns, and their inverses for decryption. PKCS#7 padding is applied. A new random 16-byte IV is generated on every save.

### Random number generation
All random material (salts, IVs, generated passwords) is produced by `CryptGenRandom` from the Windows CryptoAPI, which provides cryptographically secure randomness.

---

## Vault File Format

The vault is stored at `%APPDATA%\PasswordManager\vault.pwmv` with the following binary layout:

| Field | Size | Description |
|---|---|---|
| Magic | 4 bytes | `PWMV` — identifies the file format |
| Version | 1 byte | Format version (`0x01`) |
| Salt | 32 bytes | Random salt for AES key derivation |
| Password hash | 32 bytes | PBKDF2 verification hash |
| IV | 16 bytes | AES initialization vector |
| Ciphertext | N bytes | AES-256-CBC encrypted entry data |

---

## Building

**Requires:** MinGW-w64 g++ (available via [MSYS2](https://www.msys2.org/))

```bash
g++ -std=c++17 -O2 -DUNICODE -D_UNICODE -Iinclude \
  src/main.cpp src/crypto.cpp src/vault.cpp src/gui.cpp \
  -o PasswordManager.exe \
  -luser32 -lgdi32 -lcomctl32 -lshell32 -lcomdlg32 -ladvapi32 \
  -mwindows
```

Or with CMake:

```bash
cmake -B build
cmake --build build
```

---

## Project Structure

```
├── include/
│   ├── crypto.h       # Crypto API (SHA-256, PBKDF2, AES-256-CBC)
│   ├── vault.h        # Vault load/save/unlock interface
│   └── gui.h          # GUI entry point
├── src/
│   ├── main.cpp       # WinMain, vault path resolution
│   ├── crypto.cpp     # Full crypto implementation
│   ├── vault.cpp      # Encrypted vault I/O
│   └── gui.cpp        # Win32 GUI (login, main window, dialogs)
├── resources/
│   └── resource.rc
└── CMakeLists.txt
```

---

## Platform

Windows only — the GUI is built on the Win32 API and the RNG uses the Windows CryptoAPI.
