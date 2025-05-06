#include "cuda_impl.h"
#include "serial_impl.h"
#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdio.h>
#include <iostream>

// CUDA global variables
bool g_cuda_initialized = false;
int g_device_count = 0;
cudaDeviceProp g_device_props;

// Subkey structure for GPU
struct GPU_key_schedule {
    uint64_t subkeys[16];
};

// CUDA error checking helper
#define CHECK_CUDA_ERROR(call) { \
    cudaError_t err = call; \
    if (err != cudaSuccess) { \
        std::cerr << "CUDA error in " << __FILE__ << " at line " << __LINE__ << ": " \
            << cudaGetErrorString(err) << " (" << err << ")" << std::endl; \
        return; \
    } \
}

bool cuda_is_available() {
    int deviceCount = 0;
    cudaError_t error = cudaGetDeviceCount(&deviceCount);

    if (error != cudaSuccess) {
        return false;
    }

    return deviceCount > 0;
}

bool cuda_init() {
    if (g_cuda_initialized) {
        return true;
    }

    cudaError_t error = cudaGetDeviceCount(&g_device_count);
    if (error != cudaSuccess || g_device_count == 0) {
        std::cerr << "No CUDA-capable devices found!" << std::endl;
        return false;
    }

    error = cudaGetDeviceProperties(&g_device_props, 0);
    if (error != cudaSuccess) {
        std::cerr << "Failed to get device properties!" << std::endl;
        return false;
    }

    std::cout << "Using CUDA device: " << g_device_props.name << std::endl;
    std::cout << "Compute capability: " << g_device_props.major << "." << g_device_props.minor << std::endl;
    std::cout << "Max threads per block: " << g_device_props.maxThreadsPerBlock << std::endl;

    g_cuda_initialized = true;
    return true;
}

void cuda_cleanup() {
    if (g_cuda_initialized) {
        cudaDeviceReset();
        g_cuda_initialized = false;
    }
}

// CUDA kernel for single DES encrypt
__device__ void device_des_encrypt(uint64_t input, uint64_t* output, const GPU_key_schedule* key) {
    uint64_t block = input;

    // Apply 16 rounds of simple operations
    for (int i = 0; i < 16; i++) {
        // Split block into left and right halves
        uint32_t left = (uint32_t)(block >> 32);
        uint32_t right = (uint32_t)(block & 0xFFFFFFFF);

        // Simple Feistel function
        uint32_t f_result = right ^ (uint32_t)(key->subkeys[i]);

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

// CUDA kernel for single DES decrypt
__device__ void device_des_decrypt(uint64_t input, uint64_t* output, const GPU_key_schedule* key) {
    uint64_t block = input;

    // Apply 16 rounds of simple operations in reverse order
    for (int i = 15; i >= 0; i--) {
        // Split block into left and right halves
        uint32_t left = (uint32_t)(block >> 32);
        uint32_t right = (uint32_t)(block & 0xFFFFFFFF);

        // Simple Feistel function
        uint32_t f_result = right ^ (uint32_t)(key->subkeys[i]);

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

// CUDA kernel for single 3DES encrypt
__device__ void device_3des_encrypt(uint64_t input, uint64_t* output,
    const GPU_key_schedule* key1,
    const GPU_key_schedule* key2,
    const GPU_key_schedule* key3) {
    uint64_t temp1, temp2;
    device_des_encrypt(input, &temp1, key1);
    device_des_decrypt(temp1, &temp2, key2);
    device_des_encrypt(temp2, output, key3);
}

// CUDA kernel for single 3DES decrypt
__device__ void device_3des_decrypt(uint64_t input, uint64_t* output,
    const GPU_key_schedule* key1,
    const GPU_key_schedule* key2,
    const GPU_key_schedule* key3) {
    uint64_t temp1, temp2;
    device_des_decrypt(input, &temp1, key3);
    device_des_encrypt(temp1, &temp2, key2);
    device_des_decrypt(temp2, output, key1);
}

// CUDA kernel for ECB mode encryption
__global__ void kernel_3des_ecb_encrypt(const uint64_t* input, uint64_t* output, int num_blocks,
    const GPU_key_schedule* key1,
    const GPU_key_schedule* key2,
    const GPU_key_schedule* key3) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < num_blocks) {
        device_3des_encrypt(input[idx], &output[idx], key1, key2, key3);
    }
}

// CUDA kernel for ECB mode decryption
__global__ void kernel_3des_ecb_decrypt(const uint64_t* input, uint64_t* output, int num_blocks,
    const GPU_key_schedule* key1,
    const GPU_key_schedule* key2,
    const GPU_key_schedule* key3) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < num_blocks) {
        device_3des_decrypt(input[idx], &output[idx], key1, key2, key3);
    }
}

// CUDA kernel for CBC mode decryption (just the decryption part)
__global__ void kernel_3des_cbc_decrypt_phase1(const uint64_t* input, uint64_t* output, int num_blocks,
    const GPU_key_schedule* key1,
    const GPU_key_schedule* key2,
    const GPU_key_schedule* key3) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < num_blocks) {
        device_3des_decrypt(input[idx], &output[idx], key1, key2, key3);
    }
}

// CUDA kernel for CBC mode decryption (just the XOR part)
__global__ void kernel_3des_cbc_decrypt_phase2(const uint64_t* decrypted, uint64_t* output,
    const uint64_t* input, uint64_t iv, int num_blocks) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < num_blocks) {
        if (idx == 0) {
            output[idx] = decrypted[idx] ^ iv;
        }
        else {
            output[idx] = decrypted[idx] ^ input[idx - 1];
        }
    }
}

// Host function for CUDA ECB encrypt
void cuda_3des_ecb_encrypt(const std::vector<uint64_t>& plaintext_blocks,
    std::vector<uint64_t>& ciphertext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3) {

    if (!cuda_is_available() || !cuda_init()) {
        std::cerr << "CUDA not available, falling back to CPU implementation." << std::endl;
        serial_3des_ecb_encrypt(plaintext_blocks, ciphertext_blocks, key1, key2, key3);
        return;
    }

    size_t num_blocks = plaintext_blocks.size();
    if (num_blocks == 0) {
        return;
    }

    ciphertext_blocks.resize(num_blocks);

    // Allocate device memory
    uint64_t* d_input = nullptr;
    uint64_t* d_output = nullptr;
    GPU_key_schedule* d_key1 = nullptr;
    GPU_key_schedule* d_key2 = nullptr;
    GPU_key_schedule* d_key3 = nullptr;

    CHECK_CUDA_ERROR(cudaMalloc(&d_input, num_blocks * sizeof(uint64_t)));
    CHECK_CUDA_ERROR(cudaMalloc(&d_output, num_blocks * sizeof(uint64_t)));
    CHECK_CUDA_ERROR(cudaMalloc(&d_key1, sizeof(GPU_key_schedule)));
    CHECK_CUDA_ERROR(cudaMalloc(&d_key2, sizeof(GPU_key_schedule)));
    CHECK_CUDA_ERROR(cudaMalloc(&d_key3, sizeof(GPU_key_schedule)));

    // Copy data to device
    CHECK_CUDA_ERROR(cudaMemcpy(d_input, plaintext_blocks.data(),
        num_blocks * sizeof(uint64_t), cudaMemcpyHostToDevice));

    // Copy keys to device
    GPU_key_schedule h_key1, h_key2, h_key3;
    for (int i = 0; i < 16; i++) {
        h_key1.subkeys[i] = key1.subkeys[i];
        h_key2.subkeys[i] = key2.subkeys[i];
        h_key3.subkeys[i] = key3.subkeys[i];
    }

    CHECK_CUDA_ERROR(cudaMemcpy(d_key1, &h_key1, sizeof(GPU_key_schedule), cudaMemcpyHostToDevice));
    CHECK_CUDA_ERROR(cudaMemcpy(d_key2, &h_key2, sizeof(GPU_key_schedule), cudaMemcpyHostToDevice));
    CHECK_CUDA_ERROR(cudaMemcpy(d_key3, &h_key3, sizeof(GPU_key_schedule), cudaMemcpyHostToDevice));

    // Configure kernel
    int threadsPerBlock = 256;
    int blocksPerGrid = (num_blocks + threadsPerBlock - 1) / threadsPerBlock;

    // Launch kernel
    kernel_3des_ecb_encrypt << <blocksPerGrid, threadsPerBlock >> > (
        d_input, d_output, static_cast<int>(num_blocks), d_key1, d_key2, d_key3);

    // Check for kernel errors
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        std::cerr << "CUDA kernel error: " << cudaGetErrorString(err) << std::endl;
        // Cleanup
        cudaFree(d_input);
        cudaFree(d_output);
        cudaFree(d_key1);
        cudaFree(d_key2);
        cudaFree(d_key3);
        return;
    }

    // Copy result back to host
    CHECK_CUDA_ERROR(cudaMemcpy(ciphertext_blocks.data(), d_output,
        num_blocks * sizeof(uint64_t), cudaMemcpyDeviceToHost));

    // Cleanup
    cudaFree(d_input);
    cudaFree(d_output);
    cudaFree(d_key1);
    cudaFree(d_key2);
    cudaFree(d_key3);
}

// Host function for CUDA ECB decrypt
void cuda_3des_ecb_decrypt(const std::vector<uint64_t>& ciphertext_blocks,
    std::vector<uint64_t>& plaintext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3) {

    if (!cuda_is_available() || !cuda_init()) {
        std::cerr << "CUDA not available, falling back to CPU implementation." << std::endl;
        serial_3des_ecb_decrypt(ciphertext_blocks, plaintext_blocks, key1, key2, key3);
        return;
    }

    size_t num_blocks = ciphertext_blocks.size();
    if (num_blocks == 0) {
        return;
    }

    plaintext_blocks.resize(num_blocks);

    // Allocate device memory
    uint64_t* d_input = nullptr;
    uint64_t* d_output = nullptr;
    GPU_key_schedule* d_key1 = nullptr;
    GPU_key_schedule* d_key2 = nullptr;
    GPU_key_schedule* d_key3 = nullptr;

    CHECK_CUDA_ERROR(cudaMalloc(&d_input, num_blocks * sizeof(uint64_t)));
    CHECK_CUDA_ERROR(cudaMalloc(&d_output, num_blocks * sizeof(uint64_t)));
    CHECK_CUDA_ERROR(cudaMalloc(&d_key1, sizeof(GPU_key_schedule)));
    CHECK_CUDA_ERROR(cudaMalloc(&d_key2, sizeof(GPU_key_schedule)));
    CHECK_CUDA_ERROR(cudaMalloc(&d_key3, sizeof(GPU_key_schedule)));

    // Copy data to device
    CHECK_CUDA_ERROR(cudaMemcpy(d_input, ciphertext_blocks.data(),
        num_blocks * sizeof(uint64_t), cudaMemcpyHostToDevice));

    // Copy keys to device
    GPU_key_schedule h_key1, h_key2, h_key3;
    for (int i = 0; i < 16; i++) {
        h_key1.subkeys[i] = key1.subkeys[i];
        h_key2.subkeys[i] = key2.subkeys[i];
        h_key3.subkeys[i] = key3.subkeys[i];
    }

    CHECK_CUDA_ERROR(cudaMemcpy(d_key1, &h_key1, sizeof(GPU_key_schedule), cudaMemcpyHostToDevice));
    CHECK_CUDA_ERROR(cudaMemcpy(d_key2, &h_key2, sizeof(GPU_key_schedule), cudaMemcpyHostToDevice));
    CHECK_CUDA_ERROR(cudaMemcpy(d_key3, &h_key3, sizeof(GPU_key_schedule), cudaMemcpyHostToDevice));

    // Configure kernel
    int threadsPerBlock = 256;
    int blocksPerGrid = (num_blocks + threadsPerBlock - 1) / threadsPerBlock;

    // Launch kernel
    kernel_3des_ecb_decrypt << <blocksPerGrid, threadsPerBlock >> > (
        d_input, d_output, static_cast<int>(num_blocks), d_key1, d_key2, d_key3);

    // Check for kernel errors
    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) {
        std::cerr << "CUDA kernel error: " << cudaGetErrorString(err) << std::endl;
        // Cleanup
        cudaFree(d_input);
        cudaFree(d_output);
        cudaFree(d_key1);
        cudaFree(d_key2);
        cudaFree(d_key3);
        return;
    }

    // Copy result back to host
    CHECK_CUDA_ERROR(cudaMemcpy(plaintext_blocks.data(), d_output,
        num_blocks * sizeof(uint64_t), cudaMemcpyDeviceToHost));

    // Cleanup
    cudaFree(d_input);
    cudaFree(d_output);
    cudaFree(d_key1);
    cudaFree(d_key2);
    cudaFree(d_key3);
}

// Host function for CUDA CBC encrypt
void cuda_3des_cbc_encrypt(const std::vector<uint64_t>& plaintext_blocks,
    std::vector<uint64_t>& ciphertext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv) {
    // CBC encryption has sequential dependencies, so we use CPU implementation
    // with small GPU optimizations for individual blocks
    if (!cuda_is_available() || !cuda_init()) {
        std::cerr << "CUDA not available, falling back to CPU implementation." << std::endl;
        serial_3des_cbc_encrypt(plaintext_blocks, ciphertext_blocks, key1, key2, key3, iv);
        return;
    }

    size_t num_blocks = plaintext_blocks.size();
    if (num_blocks == 0) {
        return;
    }

    ciphertext_blocks.resize(num_blocks);

    // For small datasets, overhead of GPU setup isn't worth it
    if (num_blocks < 1000) {
        serial_3des_cbc_encrypt(plaintext_blocks, ciphertext_blocks, key1, key2, key3, iv);
        return;
    }

    // Prepare device memory for keys (will be reused for each block)
    GPU_key_schedule* d_key1 = nullptr;
    GPU_key_schedule* d_key2 = nullptr;
    GPU_key_schedule* d_key3 = nullptr;

    CHECK_CUDA_ERROR(cudaMalloc(&d_key1, sizeof(GPU_key_schedule)));
    CHECK_CUDA_ERROR(cudaMalloc(&d_key2, sizeof(GPU_key_schedule)));
    CHECK_CUDA_ERROR(cudaMalloc(&d_key3, sizeof(GPU_key_schedule)));

    // Copy keys to device
    GPU_key_schedule h_key1, h_key2, h_key3;
    for (int i = 0; i < 16; i++) {
        h_key1.subkeys[i] = key1.subkeys[i];
        h_key2.subkeys[i] = key2.subkeys[i];
        h_key3.subkeys[i] = key3.subkeys[i];
    }

    CHECK_CUDA_ERROR(cudaMemcpy(d_key1, &h_key1, sizeof(GPU_key_schedule), cudaMemcpyHostToDevice));
    CHECK_CUDA_ERROR(cudaMemcpy(d_key2, &h_key2, sizeof(GPU_key_schedule), cudaMemcpyHostToDevice));
    CHECK_CUDA_ERROR(cudaMemcpy(d_key3, &h_key3, sizeof(GPU_key_schedule), cudaMemcpyHostToDevice));

    // Process blocks sequentially due to CBC dependencies
    // but use batch processing to optimize GPU usage
    const size_t BATCH_SIZE = 1000;  // Adjust based on GPU memory
    std::vector<uint64_t> batch_input(BATCH_SIZE);
    std::vector<uint64_t> batch_output(BATCH_SIZE);

    // Device memory for batches
    uint64_t* d_batch_input = nullptr;
    uint64_t* d_batch_output = nullptr;

    CHECK_CUDA_ERROR(cudaMalloc(&d_batch_input, BATCH_SIZE * sizeof(uint64_t)));
    CHECK_CUDA_ERROR(cudaMalloc(&d_batch_output, BATCH_SIZE * sizeof(uint64_t)));

    // Initial previous block is IV
    uint64_t prev_block = iv;

    // Process in batches
    for (size_t offset = 0; offset < num_blocks; offset += BATCH_SIZE) {
        size_t current_batch_size = std::min(BATCH_SIZE, num_blocks - offset);

        // Prepare input batch (XOR with previous blocks)
        for (size_t i = 0; i < current_batch_size; i++) {
            if (i == 0 && offset == 0) {
                // First block in entire plaintext - XOR with IV
                batch_input[i] = plaintext_blocks[offset + i] ^ iv;
            }
            else if (i == 0) {
                // First block in batch - XOR with previous batch's last output
                batch_input[i] = plaintext_blocks[offset + i] ^ prev_block;
            }
            else {
                // All other blocks - XOR with previous output in this batch
                batch_input[i] = plaintext_blocks[offset + i] ^ batch_output[i - 1];
            }
        }

        // Copy batch to device
        CHECK_CUDA_ERROR(cudaMemcpy(d_batch_input, batch_input.data(),
            current_batch_size * sizeof(uint64_t), cudaMemcpyHostToDevice));

        // Configure kernel
        int threadsPerBlock = 256;
        int blocksPerGrid = (current_batch_size + threadsPerBlock - 1) / threadsPerBlock;

        // Launch kernel for batch
        kernel_3des_ecb_encrypt << <blocksPerGrid, threadsPerBlock >> > (
            d_batch_input, d_batch_output, static_cast<int>(current_batch_size), d_key1, d_key2, d_key3);

        // Check for kernel errors
        cudaError_t err = cudaGetLastError();
        if (err != cudaSuccess) {
            std::cerr << "CUDA kernel error: " << cudaGetErrorString(err) << std::endl;
            break;
        }

        // Copy batch result back to host
        CHECK_CUDA_ERROR(cudaMemcpy(batch_output.data(), d_batch_output,
            current_batch_size * sizeof(uint64_t), cudaMemcpyDeviceToHost));

        // Copy to final output
        for (size_t i = 0; i < current_batch_size; i++) {
            ciphertext_blocks[offset + i] = batch_output[i];
        }

        // Update prev_block for next batch
        prev_block = batch_output[current_batch_size - 1];
    }


    // Cleanup
    cudaFree(d_batch_input);
    cudaFree(d_batch_output);
    cudaFree(d_key1);
    cudaFree(d_key2);
    cudaFree(d_key3);
}

// Host function for CUDA CBC decrypt
// Improved version of cuda_3des_cbc_decrypt function without goto statements

void cuda_3des_cbc_decrypt(const std::vector<uint64_t>& ciphertext_blocks,
    std::vector<uint64_t>& plaintext_blocks,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv) {

    // Configuration variables for CUDA kernels - declare early
    int threadsPerBlock = 256;
    int blocksPerGrid = 0;
    cudaError_t err = cudaSuccess;
    bool use_fallback = false;

    if (!cuda_is_available() || !cuda_init()) {
        std::cerr << "CUDA not available, falling back to CPU implementation." << std::endl;
        serial_3des_cbc_decrypt(ciphertext_blocks, plaintext_blocks, key1, key2, key3, iv);
        return;
    }

    size_t num_blocks = ciphertext_blocks.size();
    if (num_blocks == 0) {
        return;
    }

    plaintext_blocks.resize(num_blocks);

    // For small datasets, overhead of GPU setup isn't worth it
    if (num_blocks < 1000) {
        serial_3des_cbc_decrypt(ciphertext_blocks, plaintext_blocks, key1, key2, key3, iv);
        return;
    }

    // Allocate device memory
    uint64_t* d_input = nullptr;
    uint64_t* d_decrypted = nullptr;
    uint64_t* d_output = nullptr;
    GPU_key_schedule* d_key1 = nullptr;
    GPU_key_schedule* d_key2 = nullptr;
    GPU_key_schedule* d_key3 = nullptr;

    // Allocate memory for input
    err = cudaMalloc(&d_input, num_blocks * sizeof(uint64_t));
    if (err != cudaSuccess) {
        std::cerr << "CUDA error in cudaMalloc for d_input: " << cudaGetErrorString(err) << std::endl;
        use_fallback = true;
    }

    // Allocate memory for decrypted data
    if (!use_fallback) {
        err = cudaMalloc(&d_decrypted, num_blocks * sizeof(uint64_t));
        if (err != cudaSuccess) {
            std::cerr << "CUDA error in cudaMalloc for d_decrypted: " << cudaGetErrorString(err) << std::endl;
            use_fallback = true;
        }
    }

    // Allocate memory for output
    if (!use_fallback) {
        err = cudaMalloc(&d_output, num_blocks * sizeof(uint64_t));
        if (err != cudaSuccess) {
            std::cerr << "CUDA error in cudaMalloc for d_output: " << cudaGetErrorString(err) << std::endl;
            use_fallback = true;
        }
    }

    // Allocate memory for keys
    if (!use_fallback) {
        err = cudaMalloc(&d_key1, sizeof(GPU_key_schedule));
        if (err != cudaSuccess) {
            std::cerr << "CUDA error in cudaMalloc for d_key1: " << cudaGetErrorString(err) << std::endl;
            use_fallback = true;
        }
    }

    if (!use_fallback) {
        err = cudaMalloc(&d_key2, sizeof(GPU_key_schedule));
        if (err != cudaSuccess) {
            std::cerr << "CUDA error in cudaMalloc for d_key2: " << cudaGetErrorString(err) << std::endl;
            use_fallback = true;
        }
    }

    if (!use_fallback) {
        err = cudaMalloc(&d_key3, sizeof(GPU_key_schedule));
        if (err != cudaSuccess) {
            std::cerr << "CUDA error in cudaMalloc for d_key3: " << cudaGetErrorString(err) << std::endl;
            use_fallback = true;
        }
    }

    // Copy data to device if no errors so far
    if (!use_fallback) {
        err = cudaMemcpy(d_input, ciphertext_blocks.data(),
            num_blocks * sizeof(uint64_t), cudaMemcpyHostToDevice);
        if (err != cudaSuccess) {
            std::cerr << "CUDA error in cudaMemcpy for d_input: " << cudaGetErrorString(err) << std::endl;
            use_fallback = true;
        }
    }

    // Copy keys to device if no errors so far
    if (!use_fallback) {
        GPU_key_schedule h_key1, h_key2, h_key3;
        for (int i = 0; i < 16; i++) {
            h_key1.subkeys[i] = key1.subkeys[i];
            h_key2.subkeys[i] = key2.subkeys[i];
            h_key3.subkeys[i] = key3.subkeys[i];
        }

        err = cudaMemcpy(d_key1, &h_key1, sizeof(GPU_key_schedule), cudaMemcpyHostToDevice);
        if (err != cudaSuccess) {
            std::cerr << "CUDA error in cudaMemcpy for d_key1: " << cudaGetErrorString(err) << std::endl;
            use_fallback = true;
        }
    }

    if (!use_fallback) {
        GPU_key_schedule h_key2;
        for (int i = 0; i < 16; i++) {
            h_key2.subkeys[i] = key2.subkeys[i];
        }

        err = cudaMemcpy(d_key2, &h_key2, sizeof(GPU_key_schedule), cudaMemcpyHostToDevice);
        if (err != cudaSuccess) {
            std::cerr << "CUDA error in cudaMemcpy for d_key2: " << cudaGetErrorString(err) << std::endl;
            use_fallback = true;
        }
    }

    if (!use_fallback) {
        GPU_key_schedule h_key3;
        for (int i = 0; i < 16; i++) {
            h_key3.subkeys[i] = key3.subkeys[i];
        }

        err = cudaMemcpy(d_key3, &h_key3, sizeof(GPU_key_schedule), cudaMemcpyHostToDevice);
        if (err != cudaSuccess) {
            std::cerr << "CUDA error in cudaMemcpy for d_key3: " << cudaGetErrorString(err) << std::endl;
            use_fallback = true;
        }
    }

    // Configure and launch kernels if no errors so far
    if (!use_fallback) {
        // Calculate block and grid dimensions
        blocksPerGrid = (num_blocks + threadsPerBlock - 1) / threadsPerBlock;

        // Phase 1: Decrypt all blocks in parallel
        kernel_3des_cbc_decrypt_phase1 << <blocksPerGrid, threadsPerBlock >> > (
            d_input, d_decrypted, static_cast<int>(num_blocks), d_key1, d_key2, d_key3);

        // Ensure kernel execution is complete
        err = cudaDeviceSynchronize();
        if (err != cudaSuccess) {
            std::cerr << "CUDA error in cudaDeviceSynchronize after phase 1: " << cudaGetErrorString(err) << std::endl;
            use_fallback = true;
        }
    }

    // Check for kernel errors
    if (!use_fallback) {
        err = cudaGetLastError();
        if (err != cudaSuccess) {
            std::cerr << "CUDA kernel error in phase 1: " << cudaGetErrorString(err) << std::endl;
            use_fallback = true;
        }
    }

    // Phase 2: Only if phase 1 succeeded
    if (!use_fallback) {
        // Phase 2: XOR with previous ciphertext blocks in parallel
        kernel_3des_cbc_decrypt_phase2 << <blocksPerGrid, threadsPerBlock >> > (
            d_decrypted, d_output, d_input, iv, static_cast<int>(num_blocks));

        // Ensure kernel execution is complete
        err = cudaDeviceSynchronize();
        if (err != cudaSuccess) {
            std::cerr << "CUDA error in cudaDeviceSynchronize after phase 2: " << cudaGetErrorString(err) << std::endl;
            use_fallback = true;
        }
    }

    // Check for kernel errors
    if (!use_fallback) {
        err = cudaGetLastError();
        if (err != cudaSuccess) {
            std::cerr << "CUDA kernel error in phase 2: " << cudaGetErrorString(err) << std::endl;
            use_fallback = true;
        }
    }

    // Copy result back to host if no errors
    if (!use_fallback) {
        err = cudaMemcpy(plaintext_blocks.data(), d_output,
            num_blocks * sizeof(uint64_t), cudaMemcpyDeviceToHost);
        if (err != cudaSuccess) {
            std::cerr << "CUDA error in cudaMemcpy for results: " << cudaGetErrorString(err) << std::endl;
            use_fallback = true;
        }
    }

    // Cleanup CUDA resources
    if (d_input) cudaFree(d_input);
    if (d_decrypted) cudaFree(d_decrypted);
    if (d_output) cudaFree(d_output);
    if (d_key1) cudaFree(d_key1);
    if (d_key2) cudaFree(d_key2);
    if (d_key3) cudaFree(d_key3);

    // If any errors occurred, fall back to CPU implementation
    if (use_fallback) {
        std::cerr << "CUDA errors detected, falling back to CPU implementation." << std::endl;
        serial_3des_cbc_decrypt(ciphertext_blocks, plaintext_blocks, key1, key2, key3, iv);
    }
}