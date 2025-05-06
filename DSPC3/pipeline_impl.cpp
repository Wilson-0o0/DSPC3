#define _CRT_SECURE_NO_WARNINGS
#include "pipeline_impl.h"
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <atomic>
#include <omp.h>

// Thread-safe queue for pipeline processing
template<typename T>
class ThreadSafeQueue {
private:
    std::queue<T> queue;
    std::mutex mutex;
    std::condition_variable cv;
    std::atomic<bool> done{ false };

public:
    void push(const T& item) {
        std::unique_lock<std::mutex> lock(mutex);
        queue.push(item);
        cv.notify_one();
    }

    bool pop(T& item) {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this] { return !queue.empty() || done.load(); });

        if (queue.empty() && done.load()) {
            return false;
        }

        item = queue.front();
        queue.pop();
        return true;
    }

    void finish() {
        done.store(true);
        cv.notify_all();
    }

    void reset() {
        std::unique_lock<std::mutex> lock(mutex);
        done.store(false);

        // Clear the queue
        std::queue<T> empty;
        std::swap(queue, empty);
    }

    size_t size() {
        std::unique_lock<std::mutex> lock(mutex);
        return queue.size();
    }
};

// Pipeline structure for ECB mode
struct PipelineItem {
    size_t index;
    uint64_t data;
};

// Helper function for single DES operation
void des_encrypt(uint64_t input, uint64_t& output, const DES_key_schedule& key) {
    DES_encrypt1(&input, &output, &key);
}

void des_decrypt(uint64_t input, uint64_t& output, const DES_key_schedule& key) {
    DES_decrypt1(&input, &output, &key);
}

void pipeline_3des_ecb_encrypt(const std::vector<uint64_t>& plaintext_blocks,
    std::vector<uint64_t>& ciphertext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3) {

    size_t num_blocks = plaintext_blocks.size();
    ciphertext_blocks.resize(num_blocks);

    // Create queues for pipeline stages
    ThreadSafeQueue<PipelineItem> stage1_2_queue;
    ThreadSafeQueue<PipelineItem> stage2_3_queue;
    ThreadSafeQueue<PipelineItem> output_queue;

    // Reset queues to clear any previous state
    stage1_2_queue.reset();
    stage2_3_queue.reset();
    output_queue.reset();

    // Stage 1: DES encryption with key1
    std::thread stage1_thread([&]() {
        for (size_t i = 0; i < num_blocks; i++) {
            PipelineItem item;
            item.index = i;

            // First DES encryption
            des_encrypt(plaintext_blocks[i], item.data, key1);

            stage1_2_queue.push(item);
        }
        stage1_2_queue.finish();
        });

    // Stage 2: DES decryption with key2
    std::thread stage2_thread([&]() {
        PipelineItem item;
        while (stage1_2_queue.pop(item)) {
            // Second DES decryption
            uint64_t temp;
            des_decrypt(item.data, temp, key2);
            item.data = temp;

            stage2_3_queue.push(item);
        }
        stage2_3_queue.finish();
        });

    // Stage 3: DES encryption with key3
    std::thread stage3_thread([&]() {
        PipelineItem item;
        while (stage2_3_queue.pop(item)) {
            // Third DES encryption
            uint64_t temp;
            des_encrypt(item.data, temp, key3);
            item.data = temp;

            output_queue.push(item);
        }
        output_queue.finish();
        });

    // Collect results
    std::thread collector_thread([&]() {
        PipelineItem item;
        while (output_queue.pop(item)) {
            ciphertext_blocks[item.index] = item.data;
        }
        });

    // Wait for all threads to complete
    stage1_thread.join();
    stage2_thread.join();
    stage3_thread.join();
    collector_thread.join();
}

void pipeline_3des_ecb_decrypt(const std::vector<uint64_t>& ciphertext_blocks,
    std::vector<uint64_t>& plaintext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3) {

    size_t num_blocks = ciphertext_blocks.size();
    plaintext_blocks.resize(num_blocks);

    // Create queues for pipeline stages
    ThreadSafeQueue<PipelineItem> stage1_2_queue;
    ThreadSafeQueue<PipelineItem> stage2_3_queue;
    ThreadSafeQueue<PipelineItem> output_queue;

    // Reset queues to clear any previous state
    stage1_2_queue.reset();
    stage2_3_queue.reset();
    output_queue.reset();

    // Stage 1: DES decryption with key3
    std::thread stage1_thread([&]() {
        for (size_t i = 0; i < num_blocks; i++) {
            PipelineItem item;
            item.index = i;

            // First DES decryption (with key3)
            des_decrypt(ciphertext_blocks[i], item.data, key3);

            stage1_2_queue.push(item);
        }
        stage1_2_queue.finish();
        });

    // Stage 2: DES encryption with key2
    std::thread stage2_thread([&]() {
        PipelineItem item;
        while (stage1_2_queue.pop(item)) {
            // Second DES encryption (with key2)
            uint64_t temp;
            des_encrypt(item.data, temp, key2);
            item.data = temp;

            stage2_3_queue.push(item);
        }
        stage2_3_queue.finish();
        });

    // Stage 3: DES decryption with key1
    std::thread stage3_thread([&]() {
        PipelineItem item;
        while (stage2_3_queue.pop(item)) {
            // Third DES decryption (with key1)
            uint64_t temp;
            des_decrypt(item.data, temp, key1);
            item.data = temp;

            output_queue.push(item);
        }
        output_queue.finish();
        });

    // Collect results
    std::thread collector_thread([&]() {
        PipelineItem item;
        while (output_queue.pop(item)) {
            plaintext_blocks[item.index] = item.data;
        }
        });

    // Wait for all threads to complete
    stage1_thread.join();
    stage2_thread.join();
    stage3_thread.join();
    collector_thread.join();
}

// For CBC mode, pipeline implementation is less efficient due to dependencies
// However, we can still use a pipeline within each block processing

void pipeline_3des_cbc_encrypt(const std::vector<uint64_t>& plaintext_blocks,
    std::vector<uint64_t>& ciphertext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv) {

    // For CBC encryption, the inherent sequential dependency makes
    // pipelining less effective. We'll use a hybrid approach.

    if (plaintext_blocks.empty()) {
        return;
    }

    ciphertext_blocks.resize(plaintext_blocks.size());

    // For small datasets, the overhead of pipeline setup isn't worth it
    // Just implement the algorithm directly rather than calling serial function
    if (plaintext_blocks.size() < 1000) {
        // Simple direct implementation without pipelining
        uint64_t prev_block = iv;

        for (size_t i = 0; i < plaintext_blocks.size(); i++) {
            // XOR with previous ciphertext block (or IV for first block)
            uint64_t xored = plaintext_blocks[i] ^ prev_block;

            // 3DES encryption
            uint64_t temp1, temp2;
            DES_encrypt1(&xored, &temp1, &key1);    // First DES encryption
            DES_decrypt1(&temp1, &temp2, &key2);    // Second DES decryption
            DES_encrypt1(&temp2, &ciphertext_blocks[i], &key3); // Third DES encryption

            // Update previous block for next iteration
            prev_block = ciphertext_blocks[i];
        }
        return;
    }

    // For larger datasets, we'll use a modified approach:
    // 1. Divide the data into chunks
    // 2. Process each chunk serially for CBC dependency
    // 3. Use parallelism within the 3DES operations

    const size_t CHUNK_SIZE = 100; // Adjust based on testing
    std::vector<uint64_t> temp_blocks(CHUNK_SIZE);

    uint64_t prev_block = iv;
    size_t processed = 0;

    while (processed < plaintext_blocks.size()) {
        size_t current_chunk = std::min(CHUNK_SIZE, plaintext_blocks.size() - processed);
        std::vector<uint64_t> chunk_result(current_chunk);

        // Process each block in the chunk
        for (size_t i = 0; i < current_chunk; i++) {
            // XOR with previous block
            uint64_t xored = plaintext_blocks[processed + i] ^ prev_block;

            // Use OpenMP for the 3DES operations on this block
            uint64_t temp1, temp2;

#pragma omp parallel sections
            {
#pragma omp section
                {
                    // First DES encryption
                    DES_encrypt1(&xored, &temp1, &key1);
                }
            }

#pragma omp parallel sections
            {
#pragma omp section
                {
                    // Second DES decryption
                    DES_decrypt1(&temp1, &temp2, &key2);
                }
            }

#pragma omp parallel sections
            {
#pragma omp section
                {
                    // Third DES encryption
                    DES_encrypt1(&temp2, &chunk_result[i], &key3);
                }
            }

            // Update previous block for CBC chaining
            prev_block = chunk_result[i];
        }

        // Copy chunk results to output
        for (size_t i = 0; i < current_chunk; i++) {
            ciphertext_blocks[processed + i] = chunk_result[i];
        }

        processed += current_chunk;
    }
}

void pipeline_3des_cbc_decrypt(const std::vector<uint64_t>& ciphertext_blocks,
    std::vector<uint64_t>& plaintext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv) {
    if (ciphertext_blocks.empty()) {
        return;
    }

    size_t num_blocks = ciphertext_blocks.size();
    plaintext_blocks.resize(num_blocks);

    // For CBC decryption, we can pipeline the decryption operations

    // First, decrypt all blocks in a pipeline
    std::vector<uint64_t> decrypted_blocks(num_blocks);
    pipeline_3des_ecb_decrypt(ciphertext_blocks, decrypted_blocks, key1, key2, key3);

    // Then, perform XOR operations
    plaintext_blocks[0] = decrypted_blocks[0] ^ iv;

    for (size_t i = 1; i < num_blocks; i++) {
        plaintext_blocks[i] = decrypted_blocks[i] ^ ciphertext_blocks[i - 1];
    }
}