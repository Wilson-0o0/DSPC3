#ifndef SERIAL_IMPL_H
#define SERIAL_IMPL_H

#include <vector>
#include <cstdint>
#include "des_impl.h"

// Helper functions for 3DES operations
void single_3des_encrypt(uint64_t input, uint64_t& output,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3);

void single_3des_decrypt(uint64_t input, uint64_t& output,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3);

// Serial 3DES with ECB mode
void serial_3des_ecb_encrypt(const std::vector<uint64_t>& plaintext_blocks,
    std::vector<uint64_t>& ciphertext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3);

void serial_3des_ecb_decrypt(const std::vector<uint64_t>& ciphertext_blocks,
    std::vector<uint64_t>& plaintext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3);

// Serial 3DES with CBC mode
void serial_3des_cbc_encrypt(const std::vector<uint64_t>& plaintext_blocks,
    std::vector<uint64_t>& ciphertext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv);

void serial_3des_cbc_decrypt(const std::vector<uint64_t>& ciphertext_blocks,
    std::vector<uint64_t>& plaintext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv);

#endif // SERIAL_IMPL_H