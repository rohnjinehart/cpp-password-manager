#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace Crypto {

// SHA-256 — returns 32-byte digest
std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);
std::vector<uint8_t> sha256(const std::string& data);

// PBKDF2-HMAC-SHA256 key derivation
std::vector<uint8_t> pbkdf2_hmac_sha256(
    const std::string& password,
    const std::vector<uint8_t>& salt,
    uint32_t iterations,
    uint32_t keylen);

// AES-256-CBC encrypt/decrypt (key must be 32 bytes, iv 16 bytes)
// encrypt returns IV prepended to ciphertext
std::vector<uint8_t> aes256cbc_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv);

std::vector<uint8_t> aes256cbc_decrypt(
    const std::vector<uint8_t>& ciphertext, // no IV prefix
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv);

// Generate cryptographically random bytes using CryptGenRandom
std::vector<uint8_t> random_bytes(size_t n);

// Constant-time compare
bool secure_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

} // namespace Crypto
