#ifndef CUDA_IMPL_H
#define CUDA_IMPL_H

#include <vector>
#include <cstdint>
#include "des_impl.h"

// Check if CUDA is available
bool cuda_is_available();

// Initialize CUDA resources - call once at program start
bool cuda_init();

// Clean up CUDA resources - call once at program end
void cuda_cleanup();

// CUDA 3DES with ECB mode
void cuda_3des_ecb_encrypt(const std::vector<uint64_t>& plaintext_blocks,
    std::vector<uint64_t>& ciphertext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3);

void cuda_3des_ecb_decrypt(const std::vector<uint64_t>& ciphertext_blocks,
    std::vector<uint64_t>& plaintext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3);

// CUDA 3DES with CBC mode
void cuda_3des_cbc_encrypt(const std::vector<uint64_t>& plaintext_blocks,
    std::vector<uint64_t>& ciphertext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv);

void cuda_3des_cbc_decrypt(const std::vector<uint64_t>& ciphertext_blocks,
    std::vector<uint64_t>& plaintext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv);

#endif // CUDA_IMPL_H