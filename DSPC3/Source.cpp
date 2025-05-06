#define _CRT_SECURE_NO_WARNINGS
#include "des_utils.h"
#include "serial_impl.h"
#include "openmp_impl.h"
#include "pipeline_impl.h"
#include "cuda_impl.h"
#include "performance.h"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstdint>
#include <direct.h>  // For _mkdir
#include <chrono>
#include <iomanip>

// Function to measure execution time
double measure_execution_time(std::function<void()> func) {
    auto start = std::chrono::high_resolution_clock::now();
    func();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    return duration.count();
}

// Enum for implementation types
enum ImplementationType {
    SERIAL = 1,
    OPENMP,
    PIPELINE,
    CUDA
};

// Enum for encryption modes
enum EncryptionMode {
    ECB = 1,
    CBC
};

// Display menu and get user choice
int get_user_choice(const std::string& prompt, int min, int max) {
    int choice;
    bool valid_input = false;

    do {
        std::cout << prompt;
        if (std::cin >> choice) {
            if (choice >= min && choice <= max) {
                valid_input = true;
            }
            else {
                std::cout << "Please enter a number between " << min << " and " << max << ".\n";
            }
        }
        else {
            std::cin.clear();  // Clear error flags
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');  // Skip bad input
            std::cout << "Invalid input. Please enter a number.\n";
        }
    } while (!valid_input);

    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');  // Clear input buffer
    return choice;
}

// Get file path from user
std::string get_file_path() {
    std::string file_path;
    std::cout << "Enter the path to the file: ";
    std::getline(std::cin, file_path);
    return file_path;
}

// Get text content from user
std::string get_text_content() {
    std::string content;
    std::cout << "Enter the text to encrypt (end with an empty line):\n";
    std::string line;
    while (std::getline(std::cin, line) && !line.empty()) {
        content += line + "\n";
    }

    if (!content.empty()) {
        content.pop_back();  // Remove the last newline
    }

    return content;
}

// Display performance results
void display_performance(const std::string& operation, double execution_time, size_t data_size) {
    double data_size_mb = data_size / (1024.0 * 1024.0);
    double throughput = data_size_mb / execution_time;

    std::cout << "\nPerformance Results:\n";
    std::cout << "--------------------\n";
    std::cout << "Operation: " << operation << "\n";
    std::cout << "Data size: " << std::fixed << std::setprecision(2) << data_size_mb << " MB\n";
    std::cout << "Execution time: " << std::fixed << std::setprecision(4) << execution_time << " seconds\n";
    std::cout << "Throughput: " << std::fixed << std::setprecision(2) << throughput << " MB/s\n";
}

int main() {
    // Create output directories
    _mkdir("data");
    _mkdir("output");

    std::cout << "===========================================\n";
    std::cout << "3DES Encryption/Decryption Interactive Tool\n";
    std::cout << "===========================================\n\n";

    // Ask user whether to input text or provide a file
    std::cout << "Choose input method:\n";
    std::cout << "1. Enter text to encrypt\n";
    std::cout << "2. Specify a file path\n";
    int input_choice = get_user_choice("Enter your choice (1-2): ", 1, 2);

    // Get the input data
    std::vector<uint8_t> input_data;
    std::string input_source;

    if (input_choice == 1) {
        // User enters text
        std::string text = get_text_content();
        input_data = std::vector<uint8_t>(text.begin(), text.end());
        input_source = "user input";
    }
    else {
        // User specifies a file
        std::string file_path = get_file_path();
        try {
            input_data = load_from_file(file_path);
            input_source = file_path;
        }
        catch (const std::exception& e) {
            std::cerr << "Error loading file: " << e.what() << std::endl;
            return 1;
        }
    }

    if (input_data.empty()) {
        std::cerr << "Error: Input data is empty!" << std::endl;
        return 1;
    }

    std::cout << "\nInput data size: " << input_data.size() << " bytes from " << input_source << "\n\n";

    // Choose implementation
    std::cout << "Choose implementation method:\n";
    std::cout << "1. Serial (Single-threaded)\n";
    std::cout << "2. OpenMP (Multi-threaded)\n";
    std::cout << "3. Pipeline\n";
    std::cout << "4. CUDA (GPU acceleration)\n";

    int impl_choice = get_user_choice("Enter your choice (1-4): ", 1, 4);
    ImplementationType implementation = static_cast<ImplementationType>(impl_choice);

    // Check if CUDA is available when selected
    if (implementation == CUDA && !cuda_is_available()) {
        std::cout << "CUDA is not available on this system. Falling back to OpenMP.\n";
        implementation = OPENMP;
    }

    // Choose mode
    std::cout << "\nChoose encryption mode:\n";
    std::cout << "1. ECB (Electronic Codebook)\n";
    std::cout << "2. CBC (Cipher Block Chaining)\n";

    int mode_choice = get_user_choice("Enter your choice (1-2): ", 1, 2);
    EncryptionMode mode = static_cast<EncryptionMode>(mode_choice);

    // Initialize 3DES keys
    std::cout << "\nGenerating encryption keys...\n";
    std::vector<uint8_t> key_data = generate_test_data(24);  // 24 bytes for three 8-byte keys
    DES_key_schedule key1, key2, key3;
    init_des_keys(key1, key2, key3, key_data);

    // Generate IV for CBC mode
    uint64_t iv = 0;
    if (mode == CBC) {
        std::vector<uint8_t> iv_data = generate_test_data(8);
        for (int i = 0; i < 8; i++) {
            iv = (iv << 8) | iv_data[i];
        }
    }

    // Prepare data for encryption
    std::vector<uint8_t> padded_data = pad_data(input_data);
    std::vector<uint64_t> plaintext_blocks = bytes_to_blocks(padded_data);
    std::vector<uint64_t> ciphertext_blocks;

    // Encryption based on selected implementation and mode
    std::string operation_name;
    double encryption_time = 0.0;

    switch (implementation) {
    case SERIAL:
        operation_name = "Serial 3DES";
        if (mode == ECB) {
            encryption_time = measure_execution_time([&]() {
                serial_3des_ecb_encrypt(plaintext_blocks, ciphertext_blocks, key1, key2, key3);
                });
        }
        else { // CBC
            encryption_time = measure_execution_time([&]() {
                serial_3des_cbc_encrypt(plaintext_blocks, ciphertext_blocks, key1, key2, key3, iv);
                });
        }
        break;

    case OPENMP:
        operation_name = "OpenMP 3DES";
        if (mode == ECB) {
            encryption_time = measure_execution_time([&]() {
                openmp_3des_ecb_encrypt(plaintext_blocks, ciphertext_blocks, key1, key2, key3);
                });
        }
        else { // CBC
            encryption_time = measure_execution_time([&]() {
                openmp_3des_cbc_encrypt(plaintext_blocks, ciphertext_blocks, key1, key2, key3, iv);
                });
        }
        break;

    case PIPELINE:
        operation_name = "Pipeline 3DES";
        if (mode == ECB) {
            encryption_time = measure_execution_time([&]() {
                pipeline_3des_ecb_encrypt(plaintext_blocks, ciphertext_blocks, key1, key2, key3);
                });
        }
        else { // CBC
            encryption_time = measure_execution_time([&]() {
                pipeline_3des_cbc_encrypt(plaintext_blocks, ciphertext_blocks, key1, key2, key3, iv);
                });
        }
        break;

    case CUDA:
        operation_name = "CUDA 3DES";
        cuda_init();
        if (mode == ECB) {
            encryption_time = measure_execution_time([&]() {
                cuda_3des_ecb_encrypt(plaintext_blocks, ciphertext_blocks, key1, key2, key3);
                });
        }
        else { // CBC
            encryption_time = measure_execution_time([&]() {
                cuda_3des_cbc_encrypt(plaintext_blocks, ciphertext_blocks, key1, key2, key3, iv);
                });
        }
        cuda_cleanup();
        break;
    }

    // Convert encrypted blocks to bytes
    std::vector<uint8_t> encrypted_data = blocks_to_bytes(ciphertext_blocks);

    // Save encrypted data
    std::string encrypted_filename = "output/encrypted_data.bin";
    save_to_file(encrypted_filename, encrypted_data);
    std::cout << "\nEncryption completed and saved to: " << encrypted_filename << "\n";

    // Display encryption performance
    display_performance(operation_name + " Encryption (" + (mode == ECB ? "ECB" : "CBC") + ")",
        encryption_time, input_data.size());

    // Decrypt data
    std::vector<uint64_t> decrypted_blocks;
    double decryption_time = 0.0;

    switch (implementation) {
    case SERIAL:
        if (mode == ECB) {
            decryption_time = measure_execution_time([&]() {
                serial_3des_ecb_decrypt(ciphertext_blocks, decrypted_blocks, key1, key2, key3);
                });
        }
        else { // CBC
            decryption_time = measure_execution_time([&]() {
                serial_3des_cbc_decrypt(ciphertext_blocks, decrypted_blocks, key1, key2, key3, iv);
                });
        }
        break;

    case OPENMP:
        if (mode == ECB) {
            decryption_time = measure_execution_time([&]() {
                openmp_3des_ecb_decrypt(ciphertext_blocks, decrypted_blocks, key1, key2, key3);
                });
        }
        else { // CBC
            decryption_time = measure_execution_time([&]() {
                openmp_3des_cbc_decrypt(ciphertext_blocks, decrypted_blocks, key1, key2, key3, iv);
                });
        }
        break;

    case PIPELINE:
        if (mode == ECB) {
            decryption_time = measure_execution_time([&]() {
                pipeline_3des_ecb_decrypt(ciphertext_blocks, decrypted_blocks, key1, key2, key3);
                });
        }
        else { // CBC
            decryption_time = measure_execution_time([&]() {
                pipeline_3des_cbc_decrypt(ciphertext_blocks, decrypted_blocks, key1, key2, key3, iv);
                });
        }
        break;

    case CUDA:
        cuda_init();
        if (mode == ECB) {
            decryption_time = measure_execution_time([&]() {
                cuda_3des_ecb_decrypt(ciphertext_blocks, decrypted_blocks, key1, key2, key3);
                });
        }
        else { // CBC
            decryption_time = measure_execution_time([&]() {
                cuda_3des_cbc_decrypt(ciphertext_blocks, decrypted_blocks, key1, key2, key3, iv);
                });
        }
        cuda_cleanup();
        break;
    }

    // Convert decrypted blocks to bytes and remove padding
    std::vector<uint8_t> decrypted_padded_data = blocks_to_bytes(decrypted_blocks);
    std::vector<uint8_t> decrypted_data = remove_padding(decrypted_padded_data);

    // Save decrypted data
    std::string decrypted_filename = "output/decrypted_data.bin";
    save_to_file(decrypted_filename, decrypted_data);
    std::cout << "\nDecryption completed and saved to: " << decrypted_filename << "\n";

    // Display decryption performance
    display_performance(operation_name + " Decryption (" + (mode == ECB ? "ECB" : "CBC") + ")",
        decryption_time, input_data.size());

    // Verify decryption
    bool success = (input_data == decrypted_data);
    std::cout << "\nVerification: " << (success ? "PASSED" : "FAILED") << "\n";

    // Display content for text files (if small enough)
    if (input_data.size() < 1024 && input_choice == 1) {
        std::cout << "\nOriginal content: " << std::endl;
        std::string original_content(input_data.begin(), input_data.end());
        std::cout << original_content << std::endl;

        std::cout << "\nEncrypted content (hex): " << std::endl;
        for (size_t i = 0; i < std::min(size_t(64), encrypted_data.size()); i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(encrypted_data[i]) << " ";
            if ((i + 1) % 16 == 0) std::cout << std::endl;
        }
        if (encrypted_data.size() > 64) std::cout << "... (truncated)" << std::endl;

        std::cout << std::dec << "\nDecrypted content: " << std::endl;
        std::string decrypted_content(decrypted_data.begin(), decrypted_data.end());
        std::cout << decrypted_content << std::endl;
    }

    // Compare with performance benchmark
    std::cout << "\nWould you like to run a full benchmark comparing all implementation methods? (y/n): ";
    std::string benchmark_choice;
    std::getline(std::cin, benchmark_choice);

    if (benchmark_choice == "y" || benchmark_choice == "Y") {
        std::cout << "\nRunning performance benchmark...\n";
        std::vector<PerformanceResult> results = run_performance_tests(input_data, key1, key2, key3, iv);
        print_results(results);

        // Save benchmark results
        save_results_to_csv("performance_results.csv", results);
        std::cout << "\nBenchmark results saved to results/performance_results.csv\n";
    }

    std::cout << "\nThank you for using the 3DES Encryption Tool!\n";
    return 0;
}