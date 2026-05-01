#pragma once
#include <string>
#include <vector>
#include <cstdint>

struct PasswordEntry {
    std::string title;
    std::string username;
    std::string password;
    std::string url;
    std::string notes;
};

class Vault {
public:
    // Returns false if file doesn't exist yet (first run)
    bool load(const std::string& path);

    // Unlock with master password; returns false if wrong password
    bool unlock(const std::string& master_password);

    // Lock the vault (clears derived key from memory)
    void lock();

    bool is_unlocked() const { return m_unlocked; }
    bool is_new() const { return m_is_new; }

    // First-time setup: set master password and create vault
    bool setup(const std::string& path, const std::string& master_password);

    // Save encrypted vault to disk
    bool save();

    const std::vector<PasswordEntry>& entries() const { return m_entries; }
    void add_entry(const PasswordEntry& e);
    void update_entry(size_t idx, const PasswordEntry& e);
    void delete_entry(size_t idx);

    bool change_master_password(const std::string& old_pw, const std::string& new_pw);

private:
    std::string m_path;
    std::vector<uint8_t> m_salt;       // 32 bytes
    std::vector<uint8_t> m_pw_hash;    // PBKDF2 hash for verification (32 bytes)
    std::vector<uint8_t> m_enc_key;    // derived AES key (in memory only)
    std::vector<PasswordEntry> m_entries;
    bool m_unlocked = false;
    bool m_is_new   = false;

    std::vector<uint8_t> derive_key(const std::string& pw, const std::vector<uint8_t>& salt);
    std::vector<uint8_t> serialize_entries() const;
    bool deserialize_entries(const std::vector<uint8_t>& data);
};
