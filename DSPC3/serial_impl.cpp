#define _CRT_SECURE_NO_WARNINGS
#include "serial_impl.h"
#include <stdexcept>

void single_3des_encrypt(uint64_t input, uint64_t& output,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3) {
    uint64_t temp;
    DES_encrypt1(&input, &temp, &key1);    // First DES encryption
    DES_decrypt1(&temp, &output, &key2);   // Second DES decryption
    DES_encrypt1(&output, &output, &key3); // Third DES encryption
}

void single_3des_decrypt(uint64_t input, uint64_t& output,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3) {
    uint64_t temp;
    DES_decrypt1(&input, &temp, &key3);    // First DES decryption (key3)
    DES_encrypt1(&temp, &output, &key2);   // Second DES encryption (key2)
    DES_decrypt1(&output, &output, &key1); // Third DES decryption (key1)
}

void serial_3des_ecb_encrypt(const std::vector<uint64_t>& plaintext_blocks,
    std::vector<uint64_t>& ciphertext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3) {
    ciphertext_blocks.resize(plaintext_blocks.size());

    for (size_t i = 0; i < plaintext_blocks.size(); i++) {
        single_3des_encrypt(plaintext_blocks[i], ciphertext_blocks[i], key1, key2, key3);
    }
}

void serial_3des_ecb_decrypt(const std::vector<uint64_t>& ciphertext_blocks,
    std::vector<uint64_t>& plaintext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3) {
    plaintext_blocks.resize(ciphertext_blocks.size());

    for (size_t i = 0; i < ciphertext_blocks.size(); i++) {
        single_3des_decrypt(ciphertext_blocks[i], plaintext_blocks[i], key1, key2, key3);
    }
}

void serial_3des_cbc_encrypt(const std::vector<uint64_t>& plaintext_blocks,
    std::vector<uint64_t>& ciphertext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv) {
    if (plaintext_blocks.empty()) {
        return;
    }

    ciphertext_blocks.resize(plaintext_blocks.size());

    // First block is XORed with IV
    uint64_t prev_block = iv;

    for (size_t i = 0; i < plaintext_blocks.size(); i++) {
        // XOR with previous ciphertext block (or IV for first block)
        uint64_t xored = plaintext_blocks[i] ^ prev_block;

        // 3DES encryption
        single_3des_encrypt(xored, ciphertext_blocks[i], key1, key2, key3);

        // Update previous block for next iteration
        prev_block = ciphertext_blocks[i];
    }
}

void serial_3des_cbc_decrypt(const std::vector<uint64_t>& ciphertext_blocks,
    std::vector<uint64_t>& plaintext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv) {
    if (ciphertext_blocks.empty()) {
        return;
    }

    plaintext_blocks.resize(ciphertext_blocks.size());

    // First block is XORed with IV
    uint64_t prev_block = iv;

    for (size_t i = 0; i < ciphertext_blocks.size(); i++) {
        // 3DES decryption
        uint64_t decrypted;
        single_3des_decrypt(ciphertext_blocks[i], decrypted, key1, key2, key3);

        // XOR with previous ciphertext block (or IV for first block)
        plaintext_blocks[i] = decrypted ^ prev_block;

        // Update previous block for next iteration
        prev_block = ciphertext_blocks[i];
    }
}