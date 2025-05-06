// mpi_impl.cpp
#define _CRT_SECURE_NO_WARNINGS
#include "mpi_impl.h"
#include <mpi.h>
#include <cstring>

// Helper functions (identical logic to OpenMP)
void single_3des_encrypt_mpi(uint64_t input, uint64_t& output,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3) {
    uint64_t temp1, temp2;
    DES_encrypt1(&input, &temp1, &key1);
    DES_decrypt1(&temp1, &temp2, &key2);
    DES_encrypt1(&temp2, &output, &key3);
}

void single_3des_decrypt_mpi(uint64_t input, uint64_t& output,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3) {
    uint64_t temp1, temp2;
    DES_decrypt1(&input, &temp1, &key3);
    DES_encrypt1(&temp1, &temp2, &key2);
    DES_decrypt1(&temp2, &output, &key1);
}

void mpi_3des_ecb_encrypt(const std::vector<uint64_t>& plaintext_blocks,
    std::vector<uint64_t>& ciphertext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3) {

    int world_rank, world_size;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

    int total_blocks = plaintext_blocks.size();
    int blocks_per_process = (total_blocks + world_size - 1) / world_size; // ceil division

    std::vector<uint64_t> local_plaintext(blocks_per_process, 0);

    // Scatter plaintext
    MPI_Scatter(plaintext_blocks.data(), blocks_per_process, MPI_UINT64_T,
        local_plaintext.data(), blocks_per_process, MPI_UINT64_T,
        0, MPI_COMM_WORLD);

    std::vector<uint64_t> local_ciphertext(blocks_per_process, 0);

    // Local encryption
    for (int i = 0; i < blocks_per_process; ++i) {
        single_3des_encrypt_mpi(local_plaintext[i], local_ciphertext[i], key1, key2, key3);
    }

    // Gather ciphertext
    if (world_rank == 0) {
        ciphertext_blocks.resize(total_blocks);
    }

    MPI_Gather(local_ciphertext.data(), blocks_per_process, MPI_UINT64_T,
        ciphertext_blocks.data(), blocks_per_process, MPI_UINT64_T,
        0, MPI_COMM_WORLD);
}

void mpi_3des_ecb_decrypt(const std::vector<uint64_t>& ciphertext_blocks,
    std::vector<uint64_t>& plaintext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3) {

    int world_rank, world_size;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

    int total_blocks = ciphertext_blocks.size();
    int blocks_per_process = (total_blocks + world_size - 1) / world_size;

    std::vector<uint64_t> local_ciphertext(blocks_per_process, 0);

    // Scatter ciphertext
    MPI_Scatter(ciphertext_blocks.data(), blocks_per_process, MPI_UINT64_T,
        local_ciphertext.data(), blocks_per_process, MPI_UINT64_T,
        0, MPI_COMM_WORLD);

    std::vector<uint64_t> local_plaintext(blocks_per_process, 0);

    // Local decryption
    for (int i = 0; i < blocks_per_process; ++i) {
        single_3des_decrypt_mpi(local_ciphertext[i], local_plaintext[i], key1, key2, key3);
    }

    // Gather plaintext
    if (world_rank == 0) {
        plaintext_blocks.resize(total_blocks);
    }

    MPI_Gather(local_plaintext.data(), blocks_per_process, MPI_UINT64_T,
        plaintext_blocks.data(), blocks_per_process, MPI_UINT64_T,
        0, MPI_COMM_WORLD);
}

void mpi_3des_cbc_encrypt(const std::vector<uint64_t>& plaintext_blocks,
    std::vector<uint64_t>& ciphertext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv) {

    // CBC encryption must be sequential (cannot parallelize), because next block depends on previous block
    if (plaintext_blocks.empty()) {
        return;
    }

    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);

    if (world_rank == 0) {
        ciphertext_blocks.resize(plaintext_blocks.size());

        uint64_t prev_block = iv;
        for (size_t i = 0; i < plaintext_blocks.size(); ++i) {
            uint64_t xored = plaintext_blocks[i] ^ prev_block;
            single_3des_encrypt_mpi(xored, ciphertext_blocks[i], key1, key2, key3);
            prev_block = ciphertext_blocks[i];
        }
    }
}

void mpi_3des_cbc_decrypt(const std::vector<uint64_t>& ciphertext_blocks,
    std::vector<uint64_t>& plaintext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv) {

    int world_rank, world_size;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

    int total_blocks = ciphertext_blocks.size();
    int blocks_per_process = (total_blocks + world_size - 1) / world_size;

    std::vector<uint64_t> local_ciphertext(blocks_per_process, 0);

    // Scatter ciphertext
    MPI_Scatter(ciphertext_blocks.data(), blocks_per_process, MPI_UINT64_T,
        local_ciphertext.data(), blocks_per_process, MPI_UINT64_T,
        0, MPI_COMM_WORLD);

    std::vector<uint64_t> local_decrypted(blocks_per_process, 0);

    // Local 3DES decryption
    for (int i = 0; i < blocks_per_process; ++i) {
        single_3des_decrypt_mpi(local_ciphertext[i], local_decrypted[i], key1, key2, key3);
    }

    // Gather all decrypted blocks
    std::vector<uint64_t> decrypted_blocks;
    if (world_rank == 0) {
        decrypted_blocks.resize(total_blocks);
    }

    MPI_Gather(local_decrypted.data(), blocks_per_process, MPI_UINT64_T,
        decrypted_blocks.data(), blocks_per_process, MPI_UINT64_T,
        0, MPI_COMM_WORLD);

    if (world_rank == 0) {
        // Now perform XOR
        plaintext_blocks.resize(total_blocks);
        plaintext_blocks[0] = decrypted_blocks[0] ^ iv;

        for (int i = 1; i < total_blocks; ++i) {
            plaintext_blocks[i] = decrypted_blocks[i] ^ ciphertext_blocks[i - 1];
        }
    }
}
