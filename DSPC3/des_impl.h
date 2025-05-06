#ifndef DES_IMPL_H
#define DES_IMPL_H

#include <cstdint>

// Type for DES key schedule
typedef struct {
    uint64_t subkeys[16];
} DES_key_schedule;

// Structure for DES block
typedef struct {
    uint8_t bytes[8];
} DES_cblock;

// Generate a key schedule from a key
void DES_set_key(const DES_cblock* key, DES_key_schedule* schedule);

// DES encryption/decryption functions
void DES_encrypt1(const uint64_t* input, uint64_t* output, const DES_key_schedule* schedule);
void DES_decrypt1(const uint64_t* input, uint64_t* output, const DES_key_schedule* schedule);

// Helper for error checking (simplified for demo)
int DES_set_key_checked(const DES_cblock* key, DES_key_schedule* schedule);

#endif // DES_IMPL_H