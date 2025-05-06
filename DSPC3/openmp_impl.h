#ifndef OPENMP_IMPL_H
#define OPENMP_IMPL_H

#include <vector>
#include <cstdint>
#include "des_impl.h"

// OpenMP parallel 3DES with ECB mode
void openmp_3des_ecb_encrypt(const std::vector<uint64_t>& plaintext_blocks,
    std::vector<uint64_t>& ciphertext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    int num_threads = -1);

void openmp_3des_ecb_decrypt(const std::vector<uint64_t>& ciphertext_blocks,
    std::vector<uint64_t>& plaintext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    int num_threads = -1);

// OpenMP parallel 3DES with CBC mode (only decryption can be fully parallelized)
void openmp_3des_cbc_encrypt(const std::vector<uint64_t>& plaintext_blocks,
    std::vector<uint64_t>& ciphertext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv,
    int num_threads = -1);

void openmp_3des_cbc_decrypt(const std::vector<uint64_t>& ciphertext_blocks,
    std::vector<uint64_t>& plaintext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv,
    int num_threads = -1);

#endif // OPENMP_IMPL_H