# C++ Password Manager and Encrypter

A Windows GUI application for storing and managing passwords. Built with C++ using the Win32 API. No third-party libraries.

## Background

This project was created in April 2025 as part of Cryptography 445 at East Texas A&M University to expand my knowledge of SHA-256 hashing and symmetric encryption by building a practical application from scratch.

## Features

- Passwords are stored in an AES-256-CBC encrypted binary vault file on disk
- The vault is protected by a master password
- Passwords are hidden by default and can be revealed per entry
- Passwords can be copied to the clipboard
- Generates random 16-character passwords using the Windows cryptographic RNG
- Each entry stores a title, username, password, URL, and notes
- The master password can be changed, which re-derives the key and re-encrypts the vault
- All crypto is implemented in C++ with no external dependencies beyond the Windows system DLLs

## Cryptography

### SHA-256
SHA-256 is the underlying hash function used throughout the application. It is implemented in pure C++ per the FIPS 180-4 specification, including the message schedule, compression function, and padding.

### HMAC-SHA256
HMAC wraps SHA-256 to produce a keyed hash, used as the building block for key derivation.

### PBKDF2-HMAC-SHA256
PBKDF2 derives a 256-bit AES key from the master password using 100,000 iterations and a random 32-byte salt. A separate PBKDF2 call with a different salt is used to produce a verification hash, so the application can confirm the correct password without storing it.

### AES-256-CBC
All vault data is encrypted with AES-256 in CBC mode. The implementation includes the full key schedule (14 rounds), SubBytes, ShiftRows, MixColumns, and their inverses. PKCS#7 padding is applied. A new random 16-byte IV is generated on every save.

### Random Number Generation
All random material (salts, IVs, generated passwords) comes from `CryptGenRandom` via the Windows CryptoAPI.

## Vault File Format

Stored at `%APPDATA%\PasswordManager\vault.pwmv`.

| Field | Size | Description |
|---|---|---|
| Magic | 4 bytes | `PWMV` |
| Version | 1 byte | `0x01` |
| Salt | 32 bytes | Random salt for AES key derivation |
| Password hash | 32 bytes | PBKDF2 verification hash |
| IV | 16 bytes | AES initialization vector |
| Ciphertext | N bytes | AES-256-CBC encrypted entry data |

## Building

Requires MinGW-w64 g++ (via [MSYS2](https://www.msys2.org/)).

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

## Project Structure

```
include/
    crypto.h       # SHA-256, PBKDF2, AES-256-CBC
    vault.h        # Vault load/save/unlock interface
    gui.h          # GUI entry point
src/
    main.cpp       # WinMain, vault path resolution
    crypto.cpp     # Crypto implementation
    vault.cpp      # Encrypted vault I/O
    gui.cpp        # Win32 GUI
resources/
    resource.rc
CMakeLists.txt
```

## Platform

Windows only. The GUI uses the Win32 API and the RNG uses the Windows CryptoAPI.
