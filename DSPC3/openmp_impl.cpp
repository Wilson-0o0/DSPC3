#define _CRT_SECURE_NO_WARNINGS
#include "openmp_impl.h"
#include <omp.h>
#include <stdexcept>

// Helper function - same as in serial implementation
void single_3des_encrypt_omp(uint64_t input, uint64_t& output,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3) {
    uint64_t temp1, temp2;
    DES_encrypt1(&input, &temp1, &key1);
    DES_decrypt1(&temp1, &temp2, &key2);
    DES_encrypt1(&temp2, &output, &key3);
}

void single_3des_decrypt_omp(uint64_t input, uint64_t& output,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3) {
    uint64_t temp1, temp2;
    DES_decrypt1(&input, &temp1, &key3);
    DES_encrypt1(&temp1, &temp2, &key2);
    DES_decrypt1(&temp2, &output, &key1);
}

void openmp_3des_ecb_encrypt(const std::vector<uint64_t>& plaintext_blocks,
    std::vector<uint64_t>& ciphertext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    int num_threads) {
    ciphertext_blocks.resize(plaintext_blocks.size());

    // Set number of threads if specified
    if (num_threads > 0) {
        omp_set_num_threads(num_threads);
    }

    // Parallelize the loop
#pragma omp parallel for
    for (int i = 0; i < static_cast<int>(plaintext_blocks.size()); i++) {
        single_3des_encrypt_omp(plaintext_blocks[i], ciphertext_blocks[i], key1, key2, key3);
    }
}

void openmp_3des_ecb_decrypt(const std::vector<uint64_t>& ciphertext_blocks,
    std::vector<uint64_t>& plaintext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    int num_threads) {
    plaintext_blocks.resize(ciphertext_blocks.size());

    // Set number of threads if specified
    if (num_threads > 0) {
        omp_set_num_threads(num_threads);
    }

    // Parallelize the loop
#pragma omp parallel for
    for (int i = 0; i < static_cast<int>(ciphertext_blocks.size()); i++) {
        single_3des_decrypt_omp(ciphertext_blocks[i], plaintext_blocks[i], key1, key2, key3);
    }
}

void openmp_3des_cbc_encrypt(const std::vector<uint64_t>& plaintext_blocks,
    std::vector<uint64_t>& ciphertext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv,
    int num_threads) {
    if (plaintext_blocks.empty()) {
        return;
    }

    ciphertext_blocks.resize(plaintext_blocks.size());

    // Set number of threads if specified
    if (num_threads > 0) {
        omp_set_num_threads(num_threads);
    }

    // CBC mode has sequential dependencies, so limited parallelism is possible
    // We can use a limited chunk size to parallelize some overhead operations
    uint64_t prev_block = iv;

    for (size_t i = 0; i < plaintext_blocks.size(); i++) {
        // XOR with previous ciphertext block (or IV for first block)
        uint64_t xored = plaintext_blocks[i] ^ prev_block;

        // 3DES encryption
        single_3des_encrypt_omp(xored, ciphertext_blocks[i], key1, key2, key3);

        // Update previous block for next iteration
        prev_block = ciphertext_blocks[i];
    }
}

void openmp_3des_cbc_decrypt(const std::vector<uint64_t>& ciphertext_blocks,
    std::vector<uint64_t>& plaintext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv,
    int num_threads) {
    if (ciphertext_blocks.empty()) {
        return;
    }

    plaintext_blocks.resize(ciphertext_blocks.size());

    // Set number of threads if specified
    if (num_threads > 0) {
        omp_set_num_threads(num_threads);
    }

    // For CBC decryption, we can parallelize in two stages

    // Stage 1: Perform all 3DES decryptions in parallel
    std::vector<uint64_t> decrypted_blocks(ciphertext_blocks.size());

#pragma omp parallel for
    for (int i = 0; i < static_cast<int>(ciphertext_blocks.size()); i++) {
        single_3des_decrypt_omp(ciphertext_blocks[i], decrypted_blocks[i], key1, key2, key3);
    }

    // Stage 2: Perform XOR operations in parallel
    // First block is special case - XOR with IV
    plaintext_blocks[0] = decrypted_blocks[0] ^ iv;

#pragma omp parallel for
    for (int i = 1; i < static_cast<int>(ciphertext_blocks.size()); i++) {
        plaintext_blocks[i] = decrypted_blocks[i] ^ ciphertext_blocks[i - 1];
    }
}