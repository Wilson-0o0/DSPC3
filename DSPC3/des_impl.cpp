#include "des_impl.h"
#include <cstring>

// Initial Permutation (IP)
const int IP_TABLE[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

// Final Permutation (FP)
const int FP_TABLE[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

// Simplified key schedule generation
// For demo purposes, we'll just derive subkeys using bit operations
void DES_set_key(const DES_cblock* key, DES_key_schedule* schedule) {
    uint64_t key_value = 0;
    for (int i = 0; i < 8; i++) {
        key_value = (key_value << 8) | key->bytes[i];
    }

    // Generate 16 subkeys using simple operations
    for (int i = 0; i < 16; i++) {
        // Rotate key bits
        key_value = ((key_value << (i + 1)) | (key_value >> (64 - (i + 1))));

        // XOR with round number for more variance
        key_value ^= (uint64_t)(i + 1);

        // Store subkey
        schedule->subkeys[i] = key_value;
    }
}

// Simplified DES encryption
void DES_encrypt1(const uint64_t* input, uint64_t* output, const DES_key_schedule* schedule) {
    uint64_t block = *input;

    // Apply 16 rounds of simple operations
    for (int i = 0; i < 16; i++) {
        // Split block into left and right halves
        uint32_t left = (uint32_t)(block >> 32);
        uint32_t right = (uint32_t)(block & 0xFFFFFFFF);

        // Simple Feistel function
        uint32_t f_result = right ^ (uint32_t)(schedule->subkeys[i]);

        // XOR left with f_result
        left ^= f_result;

        // Swap left and right (except in last round)
        if (i < 15) {
            block = ((uint64_t)right << 32) | left;
        }
        else {
            block = ((uint64_t)left << 32) | right;
        }
    }

    *output = block;
}

// Simplified DES decryption
void DES_decrypt1(const uint64_t* input, uint64_t* output, const DES_key_schedule* schedule) {
    uint64_t block = *input;

    // Apply 16 rounds of simple operations in reverse order
    for (int i = 15; i >= 0; i--) {
        // Split block into left and right halves
        uint32_t left = (uint32_t)(block >> 32);
        uint32_t right = (uint32_t)(block & 0xFFFFFFFF);

        // Simple Feistel function
        uint32_t f_result = right ^ (uint32_t)(schedule->subkeys[i]);

        // XOR left with f_result
        left ^= f_result;

        // Swap left and right (except in first round)
        if (i > 0) {
            block = ((uint64_t)right << 32) | left;
        }
        else {
            block = ((uint64_t)left << 32) | right;
        }
    }

    *output = block;
}

// Wrapper for error checking (simplified for demo)
int DES_set_key_checked(const DES_cblock* key, DES_key_schedule* schedule) {
    DES_set_key(key, schedule);
    return 0; // Always succeed in demo version
}