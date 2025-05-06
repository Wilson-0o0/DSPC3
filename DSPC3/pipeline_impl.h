#ifndef PIPELINE_IMPL_H
#define PIPELINE_IMPL_H

#include <vector>
#include <cstdint>
#include "des_impl.h"

// Pipeline 3DES with ECB mode
void pipeline_3des_ecb_encrypt(const std::vector<uint64_t>& plaintext_blocks,
    std::vector<uint64_t>& ciphertext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3);

void pipeline_3des_ecb_decrypt(const std::vector<uint64_t>& ciphertext_blocks,
    std::vector<uint64_t>& plaintext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3);

// Pipeline 3DES with CBC mode (limited effectiveness due to dependencies)
void pipeline_3des_cbc_encrypt(const std::vector<uint64_t>& plaintext_blocks,
    std::vector<uint64_t>& ciphertext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv);

void pipeline_3des_cbc_decrypt(const std::vector<uint64_t>& ciphertext_blocks,
    std::vector<uint64_t>& plaintext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv);

#endif // PIPELINE_IMPL_H