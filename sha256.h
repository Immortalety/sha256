/*
    MIT License

    Copyright (c) 2020 LekKit https://github.com/LekKit

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

#ifndef SHA256_H
#define SHA256_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>
#include <stddef.h>

struct sha256_buff {
    uint64_t data_size;
    uint32_t h[8];
    uint8_t last_chunk[64];
    uint8_t chunk_size;
};

/* Initialization, must be called before any further use */
__forceinline void sha256_init(struct sha256_buff* buff) {
    buff->h[0] = 0x6a09e667;
    buff->h[1] = 0xbb67ae85;
    buff->h[2] = 0x3c6ef372;
    buff->h[3] = 0xa54ff53a;
    buff->h[4] = 0x510e527f;
    buff->h[5] = 0x9b05688c;
    buff->h[6] = 0x1f83d9ab;
    buff->h[7] = 0x5be0cd19;
    buff->data_size = 0;
    buff->chunk_size = 0;
}

#define rotate_r(val, bits) (val >> bits | val << (32 - bits))

__forceinline static void sha256_calc_chunk(struct sha256_buff* buff, const uint8_t* chunk) {
    uint32_t k[64];
    uint32_t w[64];
    uint32_t tv[8];
    uint32_t i;

    k[0] = 0x428a2f98;
    k[1] = 0x71374491;
    k[2] = 0xb5c0fbcf;
    k[3] = 0xe9b5dba5;
    k[4] = 0x3956c25b;
    k[5] = 0x59f111f1;
    k[6] = 0x923f82a4;
    k[7] = 0xab1c5ed5;
    k[8] = 0xd807aa98;
    k[9] = 0x12835b01;
    k[10] = 0x243185be;
    k[11] = 0x550c7dc3;
    k[12] = 0x72be5d74;
    k[13] = 0x80deb1fe;
    k[14] = 0x9bdc06a7;
    k[15] = 0xc19bf174;
    k[16] = 0xe49b69c1;
    k[17] = 0xefbe4786;
    k[18] = 0x0fc19dc6;
    k[19] = 0x240ca1cc;
    k[20] = 0x2de92c6f;
    k[21] = 0x4a7484aa;
    k[22] = 0x5cb0a9dc;
    k[23] = 0x76f988da;
    k[24] = 0x983e5152;
    k[25] = 0xa831c66d;
    k[26] = 0xb00327c8;
    k[27] = 0xbf597fc7;
    k[28] = 0xc6e00bf3;
    k[29] = 0xd5a79147;
    k[30] = 0x06ca6351;
    k[31] = 0x14292967;
    k[32] = 0x27b70a85;
    k[33] = 0x2e1b2138;
    k[34] = 0x4d2c6dfc;
    k[35] = 0x53380d13;
    k[36] = 0x650a7354;
    k[37] = 0x766a0abb;
    k[38] = 0x81c2c92e;
    k[39] = 0x92722c85;
    k[40] = 0xa2bfe8a1;
    k[41] = 0xa81a664b;
    k[42] = 0xc24b8b70;
    k[43] = 0xc76c51a3;
    k[44] = 0xd192e819;
    k[45] = 0xd6990624;
    k[46] = 0xf40e3585;
    k[47] = 0x106aa070;
    k[48] = 0x19a4c116;
    k[49] = 0x1e376c08;
    k[50] = 0x2748774c;
    k[51] = 0x34b0bcb5;
    k[52] = 0x391c0cb3;
    k[53] = 0x4ed8aa4a;
    k[54] = 0x5b9cca4f;
    k[55] = 0x682e6ff3;
    k[56] = 0x748f82ee;
    k[57] = 0x78a5636f;
    k[58] = 0x84c87814;
    k[59] = 0x8cc70208;
    k[60] = 0x90befffa;
    k[61] = 0xa4506ceb;
    k[62] = 0xbef9a3f7;
    k[63] = 0xc67178f2;

    for (i=0; i<16; ++i){
        w[i] = (uint32_t) chunk[0] << 24 | (uint32_t) chunk[1] << 16 | (uint32_t) chunk[2] << 8 | (uint32_t) chunk[3];
        chunk += 4;
    }
    
    for (i=16; i<64; ++i){
        uint32_t s0 = rotate_r(w[i-15], 7) ^ rotate_r(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = rotate_r(w[i-2], 17) ^ rotate_r(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    
    for (i = 0; i < 8; ++i)
        tv[i] = buff->h[i];
    
    for (i=0; i<64; ++i){
        uint32_t S1 = rotate_r(tv[4], 6) ^ rotate_r(tv[4], 11) ^ rotate_r(tv[4], 25);
        uint32_t ch = (tv[4] & tv[5]) ^ (~tv[4] & tv[6]);
        uint32_t temp1 = tv[7] + S1 + ch + k[i] + w[i];
        uint32_t S0 = rotate_r(tv[0], 2) ^ rotate_r(tv[0], 13) ^ rotate_r(tv[0], 22);
        uint32_t maj = (tv[0] & tv[1]) ^ (tv[0] & tv[2]) ^ (tv[1] & tv[2]);
        uint32_t temp2 = S0 + maj;
        
        tv[7] = tv[6];
        tv[6] = tv[5];
        tv[5] = tv[4];
        tv[4] = tv[3] + temp1;
        tv[3] = tv[2];
        tv[2] = tv[1];
        tv[1] = tv[0];
        tv[0] = temp1 + temp2;
    }

    for (i = 0; i < 8; ++i)
        buff->h[i] += tv[i];
}

/* Process block of data of arbitary length, can be used on data streams (files, etc) */
__forceinline void sha256_update(struct sha256_buff* buff, const void* data, size_t size) {
    const uint8_t* ptr = (const uint8_t*)data;
    buff->data_size += size;
    /* If there is data left in buff, concatenate it to process as new chunk */
    if (size + buff->chunk_size >= 64) {
        uint8_t tmp_chunk[64];
        uint32_t i;
        for (i = 0; i < buff->chunk_size; ++i) {
            asm("");
            tmp_chunk[i] = buff->last_chunk[i];
        }

        for (i = 0; i < 64 - buff->chunk_size; ++i) {
            asm("");
            (tmp_chunk + buff->chunk_size)[i] = ptr[i];
        }

        ptr += (64 - buff->chunk_size);
        size -= (64 - buff->chunk_size);
        buff->chunk_size = 0;
        sha256_calc_chunk(buff, tmp_chunk);
    }
    /* Run over data chunks */
    while (size  >= 64) {
        sha256_calc_chunk(buff, ptr);
        ptr += 64;
        size -= 64; 
    }
    
    /* Save remaining data in buff, will be reused on next call or finalize */
    size_t i;
    for (i = 0; i < size; ++i) {
        asm("");
        (buff->last_chunk + buff->chunk_size)[i] = ptr[i];
    }

    buff->chunk_size += size;
}

/* Produces final hash values (digest) to be read
   If the buffer is reused later, init must be called again */
__forceinline void sha256_finalize(struct sha256_buff* buff) {
    buff->last_chunk[buff->chunk_size] = 0x80;
    buff->chunk_size++;

    uint32_t i;
    for (i = 0; i < 64 - buff->chunk_size; ++i) {
        asm("");
        (buff->last_chunk + buff->chunk_size)[i] = 0;
    }

    /* If there isn't enough space to fit int64, pad chunk with zeroes and prepare next chunk */
    if (buff->chunk_size > 56) {
        sha256_calc_chunk(buff, buff->last_chunk);
        memset(buff->last_chunk, 0, 64);
    }

    /* Add total size as big-endian int64 x8 */
    uint64_t size = buff->data_size * 8;
    for (i = 8; i > 0; --i) {
        buff->last_chunk[55+i] = size & 255;
        size >>= 8;
    }

    sha256_calc_chunk(buff, buff->last_chunk);
}

/* Read digest into 32-byte binary array */
__forceinline void sha256_read(const struct sha256_buff* buff, uint8_t* hash) {
    uint32_t i;
    for (i = 0; i < 8; i++) {
        hash[i*4] = (buff->h[i] >> 24) & 255;
        hash[i*4 + 1] = (buff->h[i] >> 16) & 255;
        hash[i*4 + 2] = (buff->h[i] >> 8) & 255;
        hash[i*4 + 3] = buff->h[i] & 255;
    }
}

__forceinline static void bin_to_hex(const void* data, uint32_t len, char* out) {
    static const char* const lut = "0123456789abcdef";
    uint32_t i;
    for (i = 0; i < len; ++i){
        uint8_t c = ((const uint8_t*)data)[i];
        out[i*2] = lut[c >> 4];
        out[i*2 + 1] = lut[c & 15];
    }
}

/* Read digest into 64-char string as hex (without null-byte) */
__forceinline void sha256_read_hex(const struct sha256_buff* buff, char* hex) {
    uint8_t hash[32];
    sha256_read(buff, hash);
    bin_to_hex(hash, 32, hex);
}

/* Hashes single contiguous block of data and reads digest into 32-byte binary array */
__forceinline void sha256_easy_hash(const void* data, size_t size, uint8_t* hash) {
    struct sha256_buff buff;
    sha256_init(&buff);
    sha256_update(&buff, data, size);
    sha256_finalize(&buff);
    sha256_read(&buff, hash);
}

/* Hashes single contiguous block of data and reads digest into 64-char string (without null-byte) */
__forceinline void sha256_easy_hash_hex(const void* data, size_t size, char* hex) {
    uint8_t hash[32];
    sha256_easy_hash(data, size, hash);
    bin_to_hex(hash, 32, hex);
}

#ifdef __cplusplus
}

#include <string>

class SHA256 {
private:
    struct sha256_buff buff;
public:
    SHA256() {
        sha256_init(&buff);
    }
    
    void update(const void* data, std::size_t size) {
        sha256_update(&buff, data, size);
    }
    
    std::string hash() {
        char hash[64];
        sha256_finalize(&buff);
        sha256_read_hex(&buff, hash);
        sha256_init(&buff);
        return std::string(hash, 64);
    }
    
    static std::string hashString(const std::string& str) {
        char hash[64];
        sha256_easy_hash_hex(str.c_str(), str.length(), hash);
        return std::string(hash, 64);
    }
};

#endif

#endif
