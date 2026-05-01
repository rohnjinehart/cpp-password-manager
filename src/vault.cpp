#include "vault.h"
#include "crypto.h"
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <cstring>

// Vault file format (binary):
//   magic[4]  = "PWMV"
//   version[1] = 0x01
//   salt[32]
//   pw_hash[32]  (PBKDF2 of master password, used for verification)
//   iv[16]
//   ciphertext[N]  (AES-256-CBC encrypted serialised entries)

static const char MAGIC[4] = {'P','W','M','V'};
static const uint8_t VERSION = 0x01;
static const uint32_t PBKDF2_ITER = 100000;

static void write_u32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back((v >> 24) & 0xff);
    buf.push_back((v >> 16) & 0xff);
    buf.push_back((v >>  8) & 0xff);
    buf.push_back( v        & 0xff);
}
static uint32_t read_u32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void write_str(std::vector<uint8_t>& buf, const std::string& s) {
    write_u32(buf, (uint32_t)s.size());
    buf.insert(buf.end(), s.begin(), s.end());
}
static bool read_str(const uint8_t* data, size_t len, size_t& pos, std::string& out) {
    if (pos + 4 > len) return false;
    uint32_t sz = read_u32(data + pos); pos += 4;
    if (pos + sz > len) return false;
    out.assign(reinterpret_cast<const char*>(data + pos), sz);
    pos += sz;
    return true;
}

std::vector<uint8_t> Vault::derive_key(const std::string& pw, const std::vector<uint8_t>& salt) {
    return Crypto::pbkdf2_hmac_sha256(pw, salt, PBKDF2_ITER, 32);
}

bool Vault::load(const std::string& path) {
    m_path = path;
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) {
        m_is_new = true;
        return false;
    }
    std::vector<uint8_t> raw((std::istreambuf_iterator<char>(f)), {});
    if (raw.size() < 4 + 1 + 32 + 32 + 16 + 16) return false;

    size_t pos = 0;
    if (memcmp(raw.data(), MAGIC, 4) != 0) return false; pos += 4;
    if (raw[pos] != VERSION) return false; pos++;
    m_salt.assign(raw.begin() + pos, raw.begin() + pos + 32); pos += 32;
    m_pw_hash.assign(raw.begin() + pos, raw.begin() + pos + 32); pos += 32;

    // Store IV + ciphertext for later use in unlock()
    // We just keep the whole raw file data and re-read on unlock
    // Re-save pos into members
    m_unlocked = false;

    // Store rest of file for use during unlock
    // Pack IV + ciphertext together in pw_hash slot temporarily — instead, just save the file path and re-read
    // Actually just store the raw bytes after the header
    // We'll stash them in a local field. Add it as a private member via a simple approach:
    // Store the file, re-read in unlock().
    return true;
}

bool Vault::unlock(const std::string& master_password) {
    if (m_is_new) return false;

    auto key = derive_key(master_password, m_salt);

    // Re-read file to get IV + ciphertext
    std::ifstream f(m_path, std::ios::binary);
    if (!f.is_open()) return false;
    std::vector<uint8_t> raw((std::istreambuf_iterator<char>(f)), {});

    size_t header = 4 + 1 + 32 + 32; // magic+ver+salt+pw_hash
    if (raw.size() < header + 16) return false;

    std::vector<uint8_t> iv(raw.begin() + header, raw.begin() + header + 16);
    std::vector<uint8_t> ct(raw.begin() + header + 16, raw.end());

    // Verify password: derive a separate verification hash
    // We use a second PBKDF2 call with a different context byte appended to salt
    std::vector<uint8_t> verify_salt = m_salt;
    verify_salt.push_back(0x00); // verification context
    auto check = Crypto::pbkdf2_hmac_sha256(master_password, verify_salt, PBKDF2_ITER, 32);
    if (!Crypto::secure_compare(check, m_pw_hash)) return false;

    try {
        auto plain = Crypto::aes256cbc_decrypt(ct, key, iv);
        if (!deserialize_entries(plain)) return false;
    } catch (...) {
        return false;
    }

    m_enc_key = key;
    m_unlocked = true;
    return true;
}

void Vault::lock() {
    m_unlocked = false;
    std::fill(m_enc_key.begin(), m_enc_key.end(), 0);
    m_enc_key.clear();
    m_entries.clear();
}

bool Vault::setup(const std::string& path, const std::string& master_password) {
    m_path = path;
    m_salt = Crypto::random_bytes(32);
    auto key = derive_key(master_password, m_salt);

    std::vector<uint8_t> verify_salt = m_salt;
    verify_salt.push_back(0x00);
    m_pw_hash = Crypto::pbkdf2_hmac_sha256(master_password, verify_salt, PBKDF2_ITER, 32);

    m_enc_key = key;
    m_unlocked = true;
    m_is_new = false;
    m_entries.clear();
    return save();
}

bool Vault::save() {
    if (!m_unlocked) return false;
    auto plain = serialize_entries();
    auto iv    = Crypto::random_bytes(16);
    auto ct    = Crypto::aes256cbc_encrypt(plain, m_enc_key, iv);

    std::ofstream f(m_path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return false;
    f.write(MAGIC, 4);
    f.put(VERSION);
    f.write(reinterpret_cast<const char*>(m_salt.data()), 32);
    f.write(reinterpret_cast<const char*>(m_pw_hash.data()), 32);
    f.write(reinterpret_cast<const char*>(iv.data()), 16);
    f.write(reinterpret_cast<const char*>(ct.data()), ct.size());
    return true;
}

void Vault::add_entry(const PasswordEntry& e) {
    m_entries.push_back(e);
}

void Vault::update_entry(size_t idx, const PasswordEntry& e) {
    if (idx < m_entries.size()) m_entries[idx] = e;
}

void Vault::delete_entry(size_t idx) {
    if (idx < m_entries.size()) m_entries.erase(m_entries.begin() + idx);
}

bool Vault::change_master_password(const std::string& old_pw, const std::string& new_pw) {
    std::vector<uint8_t> verify_salt = m_salt;
    verify_salt.push_back(0x00);
    auto check = Crypto::pbkdf2_hmac_sha256(old_pw, verify_salt, PBKDF2_ITER, 32);
    if (!Crypto::secure_compare(check, m_pw_hash)) return false;

    m_salt = Crypto::random_bytes(32);
    auto key = derive_key(new_pw, m_salt);
    verify_salt = m_salt;
    verify_salt.push_back(0x00);
    m_pw_hash = Crypto::pbkdf2_hmac_sha256(new_pw, verify_salt, PBKDF2_ITER, 32);
    m_enc_key = key;
    return save();
}

std::vector<uint8_t> Vault::serialize_entries() const {
    std::vector<uint8_t> buf;
    write_u32(buf, (uint32_t)m_entries.size());
    for (auto& e : m_entries) {
        write_str(buf, e.title);
        write_str(buf, e.username);
        write_str(buf, e.password);
        write_str(buf, e.url);
        write_str(buf, e.notes);
    }
    return buf;
}

bool Vault::deserialize_entries(const std::vector<uint8_t>& data) {
    if (data.size() < 4) return false;
    size_t pos = 0;
    uint32_t count = read_u32(data.data()); pos += 4;
    m_entries.clear();
    for (uint32_t i = 0; i < count; i++) {
        PasswordEntry e;
        if (!read_str(data.data(), data.size(), pos, e.title))    return false;
        if (!read_str(data.data(), data.size(), pos, e.username))  return false;
        if (!read_str(data.data(), data.size(), pos, e.password))  return false;
        if (!read_str(data.data(), data.size(), pos, e.url))       return false;
        if (!read_str(data.data(), data.size(), pos, e.notes))     return false;
        m_entries.push_back(e);
    }
    return true;
}
