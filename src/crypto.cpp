#include "crypto.h"
#include <stdexcept>
#include <cstring>
#include <array>
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "Advapi32.lib")

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------
namespace {

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

inline uint32_t rotr32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z)  { return (x & y) ^ (~x & z); }
inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint32_t ep0(uint32_t x) { return rotr32(x,2)  ^ rotr32(x,13) ^ rotr32(x,22); }
inline uint32_t ep1(uint32_t x) { return rotr32(x,6)  ^ rotr32(x,11) ^ rotr32(x,25); }
inline uint32_t sig0(uint32_t x){ return rotr32(x,7)  ^ rotr32(x,18) ^ (x >> 3); }
inline uint32_t sig1(uint32_t x){ return rotr32(x,17) ^ rotr32(x,19) ^ (x >> 10); }

void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)data[i*4]<<24)|((uint32_t)data[i*4+1]<<16)|((uint32_t)data[i*4+2]<<8)|data[i*4+3];
    for (int i = 16; i < 64; i++)
        w[i] = sig1(w[i-2]) + w[i-7] + sig0(w[i-15]) + w[i-16];

    uint32_t a=state[0],b=state[1],c=state[2],d=state[3],
             e=state[4],f=state[5],g=state[6],h=state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + ep1(e) + ch(e,f,g) + K256[i] + w[i];
        uint32_t t2 = ep0(a) + maj(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d;
    state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

std::vector<uint8_t> sha256_raw(const uint8_t* msg, size_t len) {
    uint32_t state[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    uint8_t block[64];
    size_t processed = 0;
    while (processed + 64 <= len) {
        sha256_transform(state, msg + processed);
        processed += 64;
    }
    size_t rem = len - processed;
    memcpy(block, msg + processed, rem);
    block[rem] = 0x80;
    if (rem >= 56) {
        memset(block + rem + 1, 0, 63 - rem);
        sha256_transform(state, block);
        memset(block, 0, 56);
    } else {
        memset(block + rem + 1, 0, 55 - rem);
    }
    uint64_t bitlen = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++)
        block[56 + i] = (uint8_t)(bitlen >> (56 - 8*i));
    sha256_transform(state, block);

    std::vector<uint8_t> digest(32);
    for (int i = 0; i < 8; i++) {
        digest[i*4]   = (state[i] >> 24) & 0xff;
        digest[i*4+1] = (state[i] >> 16) & 0xff;
        digest[i*4+2] = (state[i] >>  8) & 0xff;
        digest[i*4+3] =  state[i]        & 0xff;
    }
    return digest;
}

// HMAC-SHA256
std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& msg) {
    std::vector<uint8_t> k = key;
    if (k.size() > 64) k = sha256_raw(k.data(), k.size());
    k.resize(64, 0);
    std::vector<uint8_t> ipad(64), opad(64);
    for (int i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    std::vector<uint8_t> inner; inner.insert(inner.end(), ipad.begin(), ipad.end());
    inner.insert(inner.end(), msg.begin(), msg.end());
    auto h1 = sha256_raw(inner.data(), inner.size());
    std::vector<uint8_t> outer; outer.insert(outer.end(), opad.begin(), opad.end());
    outer.insert(outer.end(), h1.begin(), h1.end());
    return sha256_raw(outer.data(), outer.size());
}

// ---------------------------------------------------------------------------
// AES-256
// ---------------------------------------------------------------------------
static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t RSBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t RCON[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

inline uint8_t xtime(uint8_t x) { return (x << 1) ^ ((x >> 7) * 0x1b); }
inline uint8_t mul(uint8_t a, uint8_t b) {
    return ((b & 1) * a) ^
           ((b >> 1 & 1) * xtime(a)) ^
           ((b >> 2 & 1) * xtime(xtime(a))) ^
           ((b >> 3 & 1) * xtime(xtime(xtime(a)))) ^
           ((b >> 4 & 1) * xtime(xtime(xtime(xtime(a)))));
}

struct AES256 {
    uint8_t rk[240]; // 15 round keys × 16 bytes

    void key_expand(const uint8_t* key) {
        memcpy(rk, key, 32);
        int i = 8;
        while (i < 60) {
            uint8_t t[4];
            memcpy(t, rk + (i-1)*4, 4);
            if (i % 8 == 0) {
                uint8_t tmp = t[0]; t[0]=SBOX[t[1]]^RCON[i/8]; t[1]=SBOX[t[2]]; t[2]=SBOX[t[3]]; t[3]=SBOX[tmp];
            } else if (i % 8 == 4) {
                for (int j=0;j<4;j++) t[j]=SBOX[t[j]];
            }
            for (int j=0;j<4;j++) rk[i*4+j] = rk[(i-8)*4+j] ^ t[j];
            i++;
        }
    }

    void add_rk(uint8_t s[16], int round) {
        for (int i=0;i<16;i++) s[i]^=rk[round*16+i];
    }
    void sub_bytes(uint8_t s[16])  { for(int i=0;i<16;i++) s[i]=SBOX[s[i]]; }
    void rsub_bytes(uint8_t s[16]) { for(int i=0;i<16;i++) s[i]=RSBOX[s[i]]; }

    void shift_rows(uint8_t s[16]) {
        uint8_t t;
        t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
        t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
        t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
    }
    void rshift_rows(uint8_t s[16]) {
        uint8_t t;
        t=s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t;
        t=s[2]; s[2]=s[10]; s[10]=t; t=s[6]; s[6]=s[14]; s[14]=t;
        t=s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=t;
    }

    void mix_cols(uint8_t s[16]) {
        for (int i=0;i<4;i++) {
            uint8_t a=s[i*4],b=s[i*4+1],c=s[i*4+2],d=s[i*4+3];
            s[i*4]  =mul(a,2)^mul(b,3)^c^d;
            s[i*4+1]=a^mul(b,2)^mul(c,3)^d;
            s[i*4+2]=a^b^mul(c,2)^mul(d,3);
            s[i*4+3]=mul(a,3)^b^c^mul(d,2);
        }
    }
    void rmix_cols(uint8_t s[16]) {
        for (int i=0;i<4;i++) {
            uint8_t a=s[i*4],b=s[i*4+1],c=s[i*4+2],d=s[i*4+3];
            s[i*4]  =mul(a,0x0e)^mul(b,0x0b)^mul(c,0x0d)^mul(d,0x09);
            s[i*4+1]=mul(a,0x09)^mul(b,0x0e)^mul(c,0x0b)^mul(d,0x0d);
            s[i*4+2]=mul(a,0x0d)^mul(b,0x09)^mul(c,0x0e)^mul(d,0x0b);
            s[i*4+3]=mul(a,0x0b)^mul(b,0x0d)^mul(c,0x09)^mul(d,0x0e);
        }
    }

    void encrypt_block(const uint8_t in[16], uint8_t out[16]) {
        uint8_t s[16]; memcpy(s, in, 16);
        add_rk(s, 0);
        for (int r=1; r<14; r++) { sub_bytes(s); shift_rows(s); mix_cols(s); add_rk(s,r); }
        sub_bytes(s); shift_rows(s); add_rk(s, 14);
        memcpy(out, s, 16);
    }

    void decrypt_block(const uint8_t in[16], uint8_t out[16]) {
        uint8_t s[16]; memcpy(s, in, 16);
        add_rk(s, 14);
        for (int r=13; r>=1; r--) { rshift_rows(s); rsub_bytes(s); add_rk(s,r); rmix_cols(s); }
        rshift_rows(s); rsub_bytes(s); add_rk(s, 0);
        memcpy(out, s, 16);
    }
};

} // anonymous namespace

namespace Crypto {

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    return sha256_raw(data.data(), data.size());
}
std::vector<uint8_t> sha256(const std::string& data) {
    return sha256_raw(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

std::vector<uint8_t> pbkdf2_hmac_sha256(
    const std::string& password,
    const std::vector<uint8_t>& salt,
    uint32_t iterations,
    uint32_t keylen)
{
    std::vector<uint8_t> dk;
    std::vector<uint8_t> pw(password.begin(), password.end());
    uint32_t block_count = (keylen + 31) / 32;
    for (uint32_t i = 1; i <= block_count; i++) {
        std::vector<uint8_t> U;
        U.insert(U.end(), salt.begin(), salt.end());
        U.push_back((i >> 24) & 0xff); U.push_back((i >> 16) & 0xff);
        U.push_back((i >>  8) & 0xff); U.push_back( i        & 0xff);
        auto T = hmac_sha256(pw, U);
        auto prev = T;
        for (uint32_t j = 1; j < iterations; j++) {
            prev = hmac_sha256(pw, prev);
            for (int k = 0; k < 32; k++) T[k] ^= prev[k];
        }
        dk.insert(dk.end(), T.begin(), T.end());
    }
    dk.resize(keylen);
    return dk;
}

std::vector<uint8_t> aes256cbc_encrypt(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv)
{
    if (key.size() != 32 || iv.size() != 16)
        throw std::invalid_argument("AES-256-CBC: key must be 32 bytes, IV 16 bytes");

    AES256 aes; aes.key_expand(key.data());

    // PKCS#7 padding
    size_t padlen = 16 - (plaintext.size() % 16);
    std::vector<uint8_t> padded = plaintext;
    padded.insert(padded.end(), padlen, (uint8_t)padlen);

    std::vector<uint8_t> out(padded.size());
    std::vector<uint8_t> prev = iv;
    for (size_t i = 0; i < padded.size(); i += 16) {
        uint8_t block[16];
        for (int j = 0; j < 16; j++) block[j] = padded[i+j] ^ prev[j];
        aes.encrypt_block(block, out.data() + i);
        prev.assign(out.data() + i, out.data() + i + 16);
    }
    return out;
}

std::vector<uint8_t> aes256cbc_decrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& iv)
{
    if (key.size() != 32 || iv.size() != 16)
        throw std::invalid_argument("AES-256-CBC: key must be 32 bytes, IV 16 bytes");
    if (ciphertext.empty() || ciphertext.size() % 16 != 0)
        throw std::invalid_argument("AES-256-CBC: invalid ciphertext length");

    AES256 aes; aes.key_expand(key.data());
    std::vector<uint8_t> out(ciphertext.size());
    std::vector<uint8_t> prev = iv;
    for (size_t i = 0; i < ciphertext.size(); i += 16) {
        uint8_t block[16];
        aes.decrypt_block(ciphertext.data() + i, block);
        for (int j = 0; j < 16; j++) out[i+j] = block[j] ^ prev[j];
        prev.assign(ciphertext.data() + i, ciphertext.data() + i + 16);
    }
    // Remove PKCS#7 padding
    if (!out.empty()) {
        uint8_t pad = out.back();
        if (pad < 1 || pad > 16) throw std::runtime_error("AES decrypt: invalid padding");
        for (int i = 0; i < pad; i++)
            if (out[out.size()-1-i] != pad) throw std::runtime_error("AES decrypt: invalid padding");
        out.resize(out.size() - pad);
    }
    return out;
}

std::vector<uint8_t> random_bytes(size_t n) {
    std::vector<uint8_t> buf(n);
    HCRYPTPROV prov = 0;
    if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        throw std::runtime_error("CryptAcquireContext failed");
    CryptGenRandom(prov, (DWORD)n, buf.data());
    CryptReleaseContext(prov, 0);
    return buf;
}

bool secure_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

} // namespace Crypto
