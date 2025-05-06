#define _CRT_SECURE_NO_WARNINGS
#include "performance.h"
#include "des_utils.h"
#include "serial_impl.h"
#include "openmp_impl.h"
#include "pipeline_impl.h"
#include "cuda_impl.h"  // Add CUDA implementation
#include "mpi_impl.h"
#include <chrono>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <direct.h>  // For mkdir
#include <filesystem>
#include <thread>
#include <mutex>
#include <vector>
#include <string>
#include <atomic>
#include <map>

double get_time() {
    using namespace std::chrono;
    return duration<double>(high_resolution_clock::now().time_since_epoch()).count();
}

// Single-file benchmarking
std::vector<PerformanceResult> run_performance_tests(
    const std::vector<uint8_t>& test_data,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv) {

    std::vector<PerformanceResult> results;

    // Pad data and convert to blocks
    std::vector<uint8_t> padded_data = pad_data(test_data);
    std::vector<uint64_t> plaintext_blocks = bytes_to_blocks(padded_data);

    size_t data_size_mb = test_data.size() / (1024.0 * 1024.0);

    // Test configurations
    struct TestConfig {
        std::string implementation;
        std::string mode;
        std::string operation;
    };

    std::vector<TestConfig> configs = {
        {"Serial", "ECB", "Encrypt"},
        {"Serial", "ECB", "Decrypt"},
        {"Serial", "CBC", "Encrypt"},
        {"Serial", "CBC", "Decrypt"},
        {"OpenMP", "ECB", "Encrypt"},
        {"OpenMP", "ECB", "Decrypt"},
        {"OpenMP", "CBC", "Encrypt"},
        {"OpenMP", "CBC", "Decrypt"},
        {"Pipeline", "ECB", "Encrypt"},
        {"Pipeline", "ECB", "Decrypt"},
        {"Pipeline", "CBC", "Encrypt"},
        {"Pipeline", "CBC", "Decrypt"},
        {"MPI", "ECB", "Encrypt"},         // <<=== ADD THESE 4
        {"MPI", "ECB", "Decrypt"},
        {"MPI", "CBC", "Encrypt"},
        {"MPI", "CBC", "Decrypt"}
    };

    // Add CUDA tests if available
    bool cuda_available = cuda_is_available();
    if (cuda_available) {
        configs.push_back({ "CUDA", "ECB", "Encrypt" });
        configs.push_back({ "CUDA", "ECB", "Decrypt" });
        configs.push_back({ "CUDA", "CBC", "Encrypt" });
        configs.push_back({ "CUDA", "CBC", "Decrypt" });
    }

    // Placeholder for encrypted/decrypted data
    std::vector<uint64_t> output_blocks;

    // Run each test configuration
    for (const auto& config : configs) {
        std::cout << "Testing " << config.implementation << " " << config.mode << " "
            << config.operation << "..." << std::endl;

        // Prepare input data
        std::vector<uint64_t> input_blocks = plaintext_blocks;
        if (config.operation == "Decrypt") {
            // First encrypt with serial implementation to get valid ciphertext
            if (config.mode == "ECB") {
                serial_3des_ecb_encrypt(plaintext_blocks, input_blocks, key1, key2, key3);
            }
            else { // CBC
                serial_3des_cbc_encrypt(plaintext_blocks, input_blocks, key1, key2, key3, iv);
            }
        }

        // Run the test
        double start_time = get_time();

        if (config.implementation == "Serial") {
            if (config.mode == "ECB") {
                if (config.operation == "Encrypt") {
                    serial_3des_ecb_encrypt(input_blocks, output_blocks, key1, key2, key3);
                }
                else { // Decrypt
                    serial_3des_ecb_decrypt(input_blocks, output_blocks, key1, key2, key3);
                }
            }
            else { // CBC
                if (config.operation == "Encrypt") {
                    serial_3des_cbc_encrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                }
                else { // Decrypt
                    serial_3des_cbc_decrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                }
            }
        }
        else if (config.implementation == "OpenMP") {
            if (config.mode == "ECB") {
                if (config.operation == "Encrypt") {
                    openmp_3des_ecb_encrypt(input_blocks, output_blocks, key1, key2, key3);
                }
                else { // Decrypt
                    openmp_3des_ecb_decrypt(input_blocks, output_blocks, key1, key2, key3);
                }
            }
            else { // CBC
                if (config.operation == "Encrypt") {
                    openmp_3des_cbc_encrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                }
                else { // Decrypt
                    openmp_3des_cbc_decrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                }
            }
        }
        else if (config.implementation == "Pipeline") {
            if (config.mode == "ECB") {
                if (config.operation == "Encrypt") {
                    pipeline_3des_ecb_encrypt(input_blocks, output_blocks, key1, key2, key3);
                }
                else { // Decrypt
                    pipeline_3des_ecb_decrypt(input_blocks, output_blocks, key1, key2, key3);
                }
            }
            else { // CBC
                if (config.operation == "Encrypt") {
                    pipeline_3des_cbc_encrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                }
                else { // Decrypt
                    pipeline_3des_cbc_decrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                }
            }
        }
        else if (config.implementation == "CUDA") {
            if (config.mode == "ECB") {
                if (config.operation == "Encrypt") {
                    cuda_3des_ecb_encrypt(input_blocks, output_blocks, key1, key2, key3);
                }
                else { // Decrypt
                    cuda_3des_ecb_decrypt(input_blocks, output_blocks, key1, key2, key3);
                }
            }
            else { // CBC
                if (config.operation == "Encrypt") {
                    cuda_3des_cbc_encrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                }
                else { // Decrypt
                    cuda_3des_cbc_decrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                }
            }
        }
        else if (config.implementation == "MPI") {
            if (config.mode == "ECB") {
                if (config.operation == "Encrypt") {
                    mpi_3des_ecb_encrypt(input_blocks, output_blocks, key1, key2, key3);
                }
                else { // Decrypt
                    mpi_3des_ecb_decrypt(input_blocks, output_blocks, key1, key2, key3);
                }
            }
            else { // CBC
                if (config.operation == "Encrypt") {
                    mpi_3des_cbc_encrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                }
                else { // Decrypt
                    mpi_3des_cbc_decrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                }
            }
        }


        double end_time = get_time();
        double execution_time = end_time - start_time;

        // Calculate throughput
        double throughput = data_size_mb / execution_time;

        // Store result
        PerformanceResult result;
        result.implementation = config.implementation;
        result.mode = config.mode;
        result.operation = config.operation;
        result.data_size_mb = data_size_mb;
        result.execution_time = execution_time;
        result.throughput = throughput;

        // Calculate speedup against serial implementation
        result.speedup = 1.0; // Default for serial
        if (config.implementation != "Serial") {
            // Find corresponding serial result
            for (const auto& r : results) {
                if (r.implementation == "Serial" && r.mode == config.mode && r.operation == config.operation) {
                    result.speedup = r.execution_time / execution_time;
                    break;
                }
            }
        }

        results.push_back(result);

        std::cout << "  Execution time: " << std::fixed << std::setprecision(4) << execution_time << " seconds" << std::endl;
        std::cout << "  Throughput: " << std::fixed << std::setprecision(2) << throughput << " MB/s" << std::endl;
        if (config.implementation != "Serial") {
            std::cout << "  Speedup: " << std::fixed << std::setprecision(2) << result.speedup << "x" << std::endl;
        }
        std::cout << std::endl;
    }

    return results;
}

// Multi-file benchmark helper - process a single file in the benchmark
bool benchmark_process_file(const std::string& file_path,
    const std::string& output_path,
    bool is_encryption,
    const std::string& implementation,
    bool use_ecb_mode,
    const std::string& key_path,
    const std::string& iv_path,
    double& execution_time) {
    try {
        // Read input file
        std::ifstream infile(file_path, std::ios::binary);
        if (!infile) {
            std::cerr << "Error: Cannot open input file " << file_path << std::endl;
            return false;
        }

        // Read file content into a vector
        std::vector<uint8_t> file_data((std::istreambuf_iterator<char>(infile)),
            std::istreambuf_iterator<char>());
        infile.close();

        // For encryption, generate new key/IV; for decryption, load existing key/IV
        std::vector<uint8_t> key_data;
        std::vector<uint8_t> iv_data;
        uint64_t iv = 0;

        if (is_encryption) {
            // Generate new key and IV
            key_data = generate_test_data(24);
            iv_data = generate_test_data(8);

            // Convert IV to uint64_t
            for (int i = 0; i < 8; i++) {
                iv = (iv << 8) | iv_data[i];
            }

            // Save key and IV to files
            std::string actual_key_path = output_path + ".key";
            std::string actual_iv_path = output_path + ".iv";

            std::ofstream keyfile(actual_key_path, std::ios::binary);
            if (!keyfile) {
                std::cerr << "Error: Cannot create key file " << actual_key_path << std::endl;
                return false;
            }
            keyfile.write(reinterpret_cast<const char*>(key_data.data()), key_data.size());
            keyfile.close();

            std::ofstream ivfile(actual_iv_path, std::ios::binary);
            if (!ivfile) {
                std::cerr << "Error: Cannot create IV file " << actual_iv_path << std::endl;
                return false;
            }
            ivfile.write(reinterpret_cast<const char*>(iv_data.data()), iv_data.size());
            ivfile.close();
        }
        else {
            // Load key and IV from files
            if (key_path.empty() || iv_path.empty()) {
                std::cerr << "Error: Key or IV path is not specified for decryption of " << file_path << std::endl;
                return false;
            }

            std::ifstream keyfile(key_path, std::ios::binary);
            if (!keyfile) {
                std::cerr << "Error: Cannot open key file " << key_path << std::endl;
                return false;
            }
            key_data = std::vector<uint8_t>((std::istreambuf_iterator<char>(keyfile)),
                std::istreambuf_iterator<char>());
            keyfile.close();

            std::ifstream ivfile(iv_path, std::ios::binary);
            if (!ivfile) {
                std::cerr << "Error: Cannot open IV file " << iv_path << std::endl;
                return false;
            }
            iv_data = std::vector<uint8_t>((std::istreambuf_iterator<char>(ivfile)),
                std::istreambuf_iterator<char>());
            ivfile.close();

            // Convert IV to uint64_t
            if (iv_data.size() >= 8) {
                for (int i = 0; i < 8; i++) {
                    iv = (iv << 8) | iv_data[i];
                }
            }
            else {
                std::cerr << "Error: Invalid IV size in " << iv_path << std::endl;
                return false;
            }
        }

        // Initialize keys
        DES_key_schedule key1, key2, key3;
        if (key_data.size() < 24) {
            std::cerr << "Error: Invalid key size for " << file_path << std::endl;
            return false;
        }
        init_des_keys(key1, key2, key3, key_data);

        // Prepare data for processing
        std::vector<uint64_t> input_blocks;
        std::vector<uint64_t> output_blocks;

        if (is_encryption) {
            // Encryption - Pad the data
            std::vector<uint8_t> padded_data = pad_data(file_data);
            input_blocks = bytes_to_blocks(padded_data);
        }
        else {
            // Decryption - Input is already in blocks format
            input_blocks = bytes_to_blocks(file_data);
        }

        // Start timing
        auto start_time = std::chrono::high_resolution_clock::now();

        // Process based on implementation, mode, and operation
        if (implementation == "serial") {
            if (use_ecb_mode) {
                if (is_encryption) {
                    serial_3des_ecb_encrypt(input_blocks, output_blocks, key1, key2, key3);
                }
                else {
                    serial_3des_ecb_decrypt(input_blocks, output_blocks, key1, key2, key3);
                }
            }
            else {
                if (is_encryption) {
                    serial_3des_cbc_encrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                }
                else {
                    serial_3des_cbc_decrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                }
            }
        }
        else if (implementation == "openmp") {
            if (use_ecb_mode) {
                if (is_encryption) {
                    openmp_3des_ecb_encrypt(input_blocks, output_blocks, key1, key2, key3);
                }
                else {
                    openmp_3des_ecb_decrypt(input_blocks, output_blocks, key1, key2, key3);
                }
            }
            else {
                if (is_encryption) {
                    openmp_3des_cbc_encrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                }
                else {
                    openmp_3des_cbc_decrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                }
            }
        }
        else if (implementation == "pipeline") {
            if (use_ecb_mode) {
                if (is_encryption) {
                    pipeline_3des_ecb_encrypt(input_blocks, output_blocks, key1, key2, key3);
                }
                else {
                    pipeline_3des_ecb_decrypt(input_blocks, output_blocks, key1, key2, key3);
                }
            }
            else {
                if (is_encryption) {
                    pipeline_3des_cbc_encrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                }
                else {
                    pipeline_3des_cbc_decrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                }
            }
        }
        else if (implementation == "cuda") {
            if (cuda_is_available()) {
                cuda_init();
                if (use_ecb_mode) {
                    if (is_encryption) {
                        cuda_3des_ecb_encrypt(input_blocks, output_blocks, key1, key2, key3);
                    }
                    else {
                        cuda_3des_ecb_decrypt(input_blocks, output_blocks, key1, key2, key3);
                    }
                }
                else {
                    if (is_encryption) {
                        cuda_3des_cbc_encrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                    }
                    else {
                        cuda_3des_cbc_decrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                    }
                }
                cuda_cleanup();
            }
            else {
                // Fall back to OpenMP
                if (use_ecb_mode) {
                    if (is_encryption) {
                        openmp_3des_ecb_encrypt(input_blocks, output_blocks, key1, key2, key3);
                    }
                    else {
                        openmp_3des_ecb_decrypt(input_blocks, output_blocks, key1, key2, key3);
                    }
                }
                else {
                    if (is_encryption) {
                        openmp_3des_cbc_encrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                    }
                    else {
                        openmp_3des_cbc_decrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                    }
                }
            }
        }

        // End timing
        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> duration = end_time - start_time;
        execution_time = duration.count();

        // Convert to bytes and save
        std::vector<uint8_t> processed_data;
        if (is_encryption) {
            processed_data = blocks_to_bytes(output_blocks);
        }
        else {
            std::vector<uint8_t> decrypted_padded = blocks_to_bytes(output_blocks);
            processed_data = remove_padding(decrypted_padded);
        }

        std::ofstream outfile(output_path, std::ios::binary);
        if (!outfile) {
            std::cerr << "Error: Cannot open output file " << output_path << std::endl;
            return false;
        }
        outfile.write(reinterpret_cast<const char*>(processed_data.data()), processed_data.size());
        outfile.close();

        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Error processing file " << file_path << ": " << e.what() << std::endl;
        return false;
    }
}

// Multi-file benchmark function - test multiple implementations with different thread counts
std::vector<MultiBenchmarkResult> run_multi_file_benchmark(const std::string& dir_path,
    const std::string& extension,
    bool is_encryption) {
    std::vector<MultiBenchmarkResult> results;

    // Collect files
    std::vector<std::string> files;
    try {
        for (const auto& entry : std::filesystem::directory_iterator(dir_path)) {
            if (entry.is_regular_file()) {
                std::string file_path = entry.path().string();

                // Filter by extension if specified
                if (!extension.empty() && file_path.substr(file_path.find_last_of(".")) != extension) {
                    continue;
                }

                files.push_back(file_path);
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error accessing directory: " << e.what() << std::endl;
        return results;
    }

    if (files.empty()) {
        std::cout << "No matching files found for benchmark." << std::endl;
        return results;
    }

    std::cout << "\nRunning multi-file benchmark with " << files.size() << " files..." << std::endl;

    // Define implementations to test
    std::vector<std::string> implementations = { "serial", "openmp", "pipeline", "cuda" };
    // Check if CUDA is available
    if (!cuda_is_available()) {
        implementations.pop_back(); // Remove cuda if not available
    }

    // Define modes to test
    std::vector<bool> modes = { true, false }; // true = ECB, false = CBC

    // Define thread counts to test
    std::vector<int> thread_counts = { 1, 2, 4, 8 };

    // Create temporary output directory for benchmark
    std::string output_dir = "benchmark_output";
    _mkdir(output_dir.c_str());

    // Run benchmarks for each implementation, mode, and thread count
    for (const auto& impl : implementations) {
        for (const auto& use_ecb : modes) {
            std::string mode_str = use_ecb ? "ECB" : "CBC";

            for (int threads : thread_counts) {
                std::cout << "Testing " << impl << " (" << mode_str << ") with "
                    << threads << " threads..." << std::endl;

                // Prepare tasks list
                std::vector<std::pair<std::string, std::string>> file_pairs; // input, output paths
                std::map<std::string, std::pair<std::string, std::string>> key_iv_paths; // For decryption

                for (const auto& file : files) {
                    std::string filename = std::filesystem::path(file).filename().string();
                    std::string output_path = output_dir + "/" +
                        (is_encryption ? "enc_" : "dec_") + impl + "_" + mode_str + "_" +
                        std::to_string(threads) + "_" + filename;

                    file_pairs.push_back(std::make_pair(file, output_path));

                    // For decryption, find key/IV files
                    if (!is_encryption) {
                        // If decrypting, look for key and IV files
                        std::string expected_enc_file = dir_path + "/enc_" + filename;
                        std::string key_path = expected_enc_file + ".key";
                        std::string iv_path = expected_enc_file + ".iv";

                        // Check if files exist
                        std::ifstream key_test(key_path);
                        std::ifstream iv_test(iv_path);

                        if (key_test && iv_test) {
                            key_iv_paths[file] = std::make_pair(key_path, iv_path);
                        }
                        else {
                            // Try alternative locations
                            key_path = file + ".key";
                            iv_path = file + ".iv";

                            key_test = std::ifstream(key_path);
                            iv_test = std::ifstream(iv_path);

                            if (key_test && iv_test) {
                                key_iv_paths[file] = std::make_pair(key_path, iv_path);
                            }
                            else {
                                std::cout << "Warning: Could not find key/IV files for " << file << std::endl;
                                // Keep going, we'll handle missing files later
                            }
                        }
                    }
                }

                // Set up thread pool for processing
                std::vector<std::thread> thread_pool;
                std::mutex results_mutex;
                std::atomic<size_t> file_index(0);
                std::atomic<size_t> successful_count(0);
                std::atomic<size_t> total_bytes(0);

                // Start timing
                auto start_time = std::chrono::high_resolution_clock::now();

                // Create threads
                for (int t = 0; t < threads; t++) {
                    thread_pool.emplace_back([&]() {
                        while (true) {
                            // Get next file index to process
                            size_t idx = file_index.fetch_add(1);
                            if (idx >= file_pairs.size()) break;

                            // Get file info
                            std::string input_file = file_pairs[idx].first;
                            std::string output_file = file_pairs[idx].second;

                            // Get key/IV paths for decryption
                            std::string key_path, iv_path;
                            if (!is_encryption) {
                                if (key_iv_paths.find(input_file) == key_iv_paths.end()) {
                                    // Skip files without key/IV
                                    continue;
                                }
                                key_path = key_iv_paths[input_file].first;
                                iv_path = key_iv_paths[input_file].second;
                            }

                            // Process the file
                            double file_time = 0.0;
                            bool success = benchmark_process_file(
                                input_file, output_file, is_encryption, impl, use_ecb,
                                key_path, iv_path, file_time);

                            if (success) {
                                successful_count++;

                                // Add file size to total
                                std::ifstream file(input_file, std::ios::binary | std::ios::ate);
                                if (file) {
                                    total_bytes += file.tellg();
                                    file.close();
                                }
                            }
                        }
                        });
                }

                // Wait for all threads to finish
                for (auto& t : thread_pool) {
                    if (t.joinable()) t.join();
                }

                // End timing
                auto end_time = std::chrono::high_resolution_clock::now();
                std::chrono::duration<double> duration = end_time - start_time;
                double total_time = duration.count();

                // Create result
                MultiBenchmarkResult result;
                result.thread_count = threads;
                result.file_count = successful_count;
                result.total_bytes = total_bytes;
                result.total_time = total_time;
                result.throughput = (total_bytes / (1024.0 * 1024.0)) / total_time;
                result.implementation = impl;
                result.mode = mode_str;
                result.is_encryption = is_encryption;

                results.push_back(result);

                std::cout << "  Completed " << successful_count << " files in "
                    << std::fixed << std::setprecision(3) << total_time << " seconds" << std::endl;
                std::cout << "  Throughput: " << std::fixed << std::setprecision(2)
                    << result.throughput << " MB/s" << std::endl;
            }
        }
    }

    return results;
}

void save_results_to_csv(const std::string& filename,
    const std::vector<PerformanceResult>& results) {
    // Create results directory if it doesn't exist - Linux compatible
    _mkdir("results");

    std::string filepath = "results/" + filename;
    std::ofstream file(filepath);
    if (!file) {
        std::cerr << "Error: Could not open file " << filepath << " for writing." << std::endl;
        return;
    }

    // Write header
    file << "Implementation,Mode,Operation,Data Size (MB),Execution Time (s),Throughput (MB/s),Speedup\n";

    // Write data
    for (const auto& result : results) {
        file << result.implementation << ","
            << result.mode << ","
            << result.operation << ","
            << std::fixed << std::setprecision(2) << result.data_size_mb << ","
            << std::fixed << std::setprecision(4) << result.execution_time << ","
            << std::fixed << std::setprecision(2) << result.throughput << ","
            << std::fixed << std::setprecision(2) << result.speedup << "\n";
    }

    file.close();
}

void print_results(const std::vector<PerformanceResult>& results) {
    // Calculate column widths
    size_t impl_width = 12; // "Implementation"
    size_t mode_width = 4;  // "Mode"
    size_t op_width = 10;   // "Operation"

    // Print header
    std::cout << std::left << std::setw(impl_width) << "Implementation"
        << std::setw(mode_width) << "Mode"
        << std::setw(op_width) << "Operation"
        << std::right << std::setw(12) << "Data Size (MB)"
        << std::setw(18) << "Exec Time (s)"
        << std::setw(16) << "Throughput (MB/s)"
        << std::setw(10) << "Speedup" << std::endl;

    std::cout << std::string(impl_width + mode_width + op_width + 12 + 18 + 16 + 10, '-') << std::endl;

    // Print rows
    for (const auto& result : results) {
        std::cout << std::left << std::setw(impl_width) << result.implementation
            << std::setw(mode_width) << result.mode
            << std::setw(op_width) << result.operation
            << std::right << std::setw(12) << std::fixed << std::setprecision(2) << result.data_size_mb
            << std::setw(18) << std::fixed << std::setprecision(4) << result.execution_time
            << std::setw(16) << std::fixed << std::setprecision(2) << result.throughput
            << std::setw(10) << std::fixed << std::setprecision(2) << result.speedup << std::endl;
    }
}

// Save multi-file benchmark results to CSV
void save_multi_benchmark_results(const std::string& filename, const std::vector<MultiBenchmarkResult>& results) {
    // Create results directory if it doesn't exist
    _mkdir("results");

    std::ofstream file("results/" + filename);
    if (!file) {
        std::cerr << "Error: Could not open file " << filename << " for writing." << std::endl;
        return;
    }

    // Write header
    file << "Implementation,Mode,Operation,Thread Count,File Count,Total Size (MB),Total Time (s),Throughput (MB/s)\n";

    // Write data
    for (const auto& result : results) {
        file << result.implementation << ","
            << result.mode << ","
            << (result.is_encryption ? "Encryption" : "Decryption") << ","
            << result.thread_count << ","
            << result.file_count << ","
            << std::fixed << std::setprecision(2) << (result.total_bytes / (1024.0 * 1024.0)) << ","
            << std::fixed << std::setprecision(4) << result.total_time << ","
            << std::fixed << std::setprecision(2) << result.throughput << "\n";
    }

    file.close();
}

// Print multi-file benchmark results
void print_multi_benchmark_results(const std::vector<MultiBenchmarkResult>& results) {
    std::cout << "\nMulti-File Benchmark Results:\n";
    std::cout << "============================\n\n";

    std::cout << std::left << std::setw(12) << "Impl"
        << std::setw(6) << "Mode"
        << std::setw(10) << "Operation"
        << std::right << std::setw(8) << "Threads"
        << std::setw(10) << "Files"
        << std::setw(12) << "Size (MB)"
        << std::setw(12) << "Time (s)"
        << std::setw(15) << "Throughput (MB/s)" << std::endl;

    std::cout << std::string(85, '-') << std::endl;

    for (const auto& result : results) {
        std::cout << std::left << std::setw(12) << result.implementation
            << std::setw(6) << result.mode
            << std::setw(10) << (result.is_encryption ? "Encrypt" : "Decrypt")
            << std::right << std::setw(8) << result.thread_count
            << std::setw(10) << result.file_count
            << std::fixed << std::setprecision(2) << std::setw(12) << (result.total_bytes / (1024.0 * 1024.0))
            << std::fixed << std::setprecision(3) << std::setw(12) << result.total_time
            << std::fixed << std::setprecision(2) << std::setw(15) << result.throughput << std::endl;
    }
}