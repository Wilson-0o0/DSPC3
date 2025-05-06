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
#include <direct.h>  // For mkdir
#include <chrono>
#include <iomanip>
#include <limits>
#include <functional>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <filesystem>
#include <algorithm>
#include <map>
#include "mpi_impl.h"  // <<< ADD this for MPI
#include <mpi.h>

// Function to measure execution time
double measure_execution_time(std::function<void()> func) {
    auto start = std::chrono::high_resolution_clock::now();
    func();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end - start;
    return duration.count();
}

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
    std::cout << "Data size: " << std::fixed << std::setprecision(6) << data_size_mb << " MB\n";
    std::cout << "Execution time: " << std::fixed << std::setprecision(6) << execution_time << " seconds\n";
    std::cout << "Throughput: " << std::fixed << std::setprecision(4) << throughput << " MB/s\n";
}

// Enhanced verification function
bool verify_data(const std::vector<uint8_t>& original, const std::vector<uint8_t>& decrypted, bool verbose = true) {
    if (original.size() != decrypted.size()) {
        if (verbose) {
            std::cout << "Verification failed: Size mismatch" << std::endl;
            std::cout << "Original size: " << original.size() << " bytes" << std::endl;
            std::cout << "Decrypted size: " << decrypted.size() << " bytes" << std::endl;
        }
        return false;
    }

    size_t diff_count = 0;
    size_t first_diff_pos = 0;
    bool first_diff_found = false;

    for (size_t i = 0; i < original.size(); i++) {
        if (original[i] != decrypted[i]) {
            diff_count++;
            if (!first_diff_found) {
                first_diff_pos = i;
                first_diff_found = true;
            }

            // Limit the number of differences to report
            if (diff_count > 10 && !verbose) break;
        }
    }

    if (diff_count > 0 && verbose) {
        std::cout << "Verification failed: " << diff_count << " differences found" << std::endl;
        std::cout << "First difference at byte position: " << first_diff_pos << std::endl;

        // Print a small section around the first difference
        size_t start = (first_diff_pos > 5) ? first_diff_pos - 5 : 0;
        size_t end = std::min(original.size(), first_diff_pos + 6);

        std::cout << "Original bytes around first difference (hex): ";
        for (size_t i = start; i < end; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(original[i]) << " ";
        }
        std::cout << std::dec << std::endl;

        std::cout << "Decrypted bytes around first difference (hex): ";
        for (size_t i = start; i < end; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(decrypted[i]) << " ";
        }
        std::cout << std::dec << std::endl;
    }

    return (diff_count == 0);
}

// Helper function to hex dump a portion of data
void hex_dump(const std::vector<uint8_t>& data, size_t offset, size_t length, const std::string& label) {
    if (data.empty() || offset >= data.size()) return;

    length = std::min(length, data.size() - offset);

    std::cout << label << " (offset " << offset << ", " << length << " bytes):" << std::endl;

    for (size_t i = 0; i < length; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[offset + i]) << " ";
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }

    if (length % 16 != 0) std::cout << std::endl;
    std::cout << std::dec; // Reset to decimal
}

// Define a structure to hold file processing tasks
struct FileTask {
    std::string input_path;
    std::string output_path;
    bool is_encryption;
    std::string implementation;
    bool use_ecb_mode;
    // For decryption, store the paths to key and IV files
    std::string key_path;
    std::string iv_path;
};


// Thread-safe queue for file tasks
class FileTaskQueue {
private:
    std::queue<FileTask> tasks;
    std::mutex mutex;
    std::condition_variable cv;
    std::atomic<bool> done{ false };

public:
    void push(const FileTask& task) {
        std::unique_lock<std::mutex> lock(mutex);
        tasks.push(task);
        cv.notify_one();
    }

    bool pop(FileTask& task) {
        std::unique_lock<std::mutex> lock(mutex);
        cv.wait(lock, [this] { return !tasks.empty() || done.load(); });

        if (tasks.empty() && done.load()) {
            return false;
        }

        task = tasks.front();
        tasks.pop();
        return true;
    }

    void finish() {
        done.store(true);
        cv.notify_all();
    }

    size_t size() {
        std::unique_lock<std::mutex> lock(mutex);
        return tasks.size();
    }
};

// Function to process a single file (to be called in a thread)
bool process_file(const FileTask& task) {
    try {
        std::cout << "Processing file: " << task.input_path << std::endl;

        // Read input file
        std::ifstream infile(task.input_path, std::ios::binary);
        if (!infile) {
            std::cerr << "Error: Cannot open input file " << task.input_path << std::endl;
            return false;
        }

        // Read file content into a vector
        std::vector<uint8_t> file_data((std::istreambuf_iterator<char>(infile)),
            std::istreambuf_iterator<char>());
        infile.close();

        std::cout << "File size: " << file_data.size() << " bytes" << std::endl;

        // For encryption, generate new key/IV; for decryption, load existing key/IV
        std::vector<uint8_t> key_data;
        std::vector<uint8_t> iv_data;
        uint64_t iv = 0;

        if (task.is_encryption) {
            // Generate new key and IV
            key_data = generate_test_data(24);
            iv_data = generate_test_data(8);

            // Convert IV to uint64_t
            for (int i = 0; i < 8; i++) {
                iv = (iv << 8) | iv_data[i];
            }

            // Save key and IV to files
            std::string key_path = task.output_path + ".key";
            std::string iv_path = task.output_path + ".iv";

            std::ofstream keyfile(key_path, std::ios::binary);
            if (!keyfile) {
                std::cerr << "Error: Cannot create key file " << key_path << std::endl;
                return false;
            }
            keyfile.write(reinterpret_cast<const char*>(key_data.data()), key_data.size());
            keyfile.close();

            std::ofstream ivfile(iv_path, std::ios::binary);
            if (!ivfile) {
                std::cerr << "Error: Cannot create IV file " << iv_path << std::endl;
                return false;
            }
            ivfile.write(reinterpret_cast<const char*>(iv_data.data()), iv_data.size());
            ivfile.close();
        }
        else {
            // Load key and IV from files
            if (task.key_path.empty() || task.iv_path.empty()) {
                std::cerr << "Error: Key or IV path is not specified for decryption of " << task.input_path << std::endl;
                return false;
            }

            std::ifstream keyfile(task.key_path, std::ios::binary);
            if (!keyfile) {
                std::cerr << "Error: Cannot open key file " << task.key_path << std::endl;
                return false;
            }
            key_data = std::vector<uint8_t>((std::istreambuf_iterator<char>(keyfile)),
                std::istreambuf_iterator<char>());
            keyfile.close();

            std::ifstream ivfile(task.iv_path, std::ios::binary);
            if (!ivfile) {
                std::cerr << "Error: Cannot open IV file " << task.iv_path << std::endl;
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
                std::cerr << "Error: Invalid IV size in " << task.iv_path << std::endl;
                return false;
            }
        }

        // Initialize keys
        DES_key_schedule key1, key2, key3;
        if (key_data.size() < 24) {
            std::cerr << "Error: Invalid key size for " << task.input_path << std::endl;
            return false;
        }
        init_des_keys(key1, key2, key3, key_data);

        // Prepare data for processing
        std::vector<uint64_t> input_blocks;
        std::vector<uint64_t> output_blocks;
        double operation_time = 0.0;
        std::string operation_name;

        if (task.is_encryption) {
            // Encryption - Pad the data
            std::vector<uint8_t> padded_data = pad_data(file_data);
            input_blocks = bytes_to_blocks(padded_data);

            if (task.implementation == "serial") {
                operation_name = "Serial 3DES";
                if (task.use_ecb_mode) {
                    operation_time = measure_execution_time([&]() {
                        serial_3des_ecb_encrypt(input_blocks, output_blocks, key1, key2, key3);
                        });
                }
                else {
                    operation_time = measure_execution_time([&]() {
                        serial_3des_cbc_encrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                        });
                }
            }
            else if (task.implementation == "openmp") {
                operation_name = "OpenMP 3DES";
                if (task.use_ecb_mode) {
                    operation_time = measure_execution_time([&]() {
                        openmp_3des_ecb_encrypt(input_blocks, output_blocks, key1, key2, key3);
                        });
                }
                else {
                    operation_time = measure_execution_time([&]() {
                        openmp_3des_cbc_encrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                        });
                }
            }
            else if (task.implementation == "pipeline") {
                operation_name = "Pipeline 3DES";
                if (task.use_ecb_mode) {
                    operation_time = measure_execution_time([&]() {
                        pipeline_3des_ecb_encrypt(input_blocks, output_blocks, key1, key2, key3);
                        });
                }
                else {
                    operation_time = measure_execution_time([&]() {
                        pipeline_3des_cbc_encrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                        });
                }
            }
            else if (task.implementation == "cuda") {
                operation_name = "CUDA 3DES";
                if (cuda_is_available()) {
                    cuda_init();
                    if (task.use_ecb_mode) {
                        operation_time = measure_execution_time([&]() {
                            cuda_3des_ecb_encrypt(input_blocks, output_blocks, key1, key2, key3);
                            });
                    }
                    else {
                        operation_time = measure_execution_time([&]() {
                            cuda_3des_cbc_encrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                            });
                    }
                    cuda_cleanup();
                }
                else {
                    std::cout << "CUDA not available, falling back to OpenMP for " << task.input_path << std::endl;
                    operation_name = "OpenMP 3DES (fallback)";
                    if (task.use_ecb_mode) {
                        operation_time = measure_execution_time([&]() {
                            openmp_3des_ecb_encrypt(input_blocks, output_blocks, key1, key2, key3);
                            });
                    }
                    else {
                        operation_time = measure_execution_time([&]() {
                            openmp_3des_cbc_encrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                            });
                    }
                }
            }
            else if (task.implementation == "mpi") {
                operation_name = "MPI 3DES";
                MPI_Init(nullptr, nullptr);  // <<< Initialize MPI
                if (task.use_ecb_mode) {
                    operation_time = measure_execution_time([&]() {
                        mpi_3des_ecb_encrypt(input_blocks, output_blocks, key1, key2, key3);
                        });
                }
                else {
                    operation_time = measure_execution_time([&]() {
                        mpi_3des_cbc_encrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                        });
                }
                MPI_Finalize();  // <<< Finalize MPI
            }


            // Display encryption performance
            display_performance(operation_name + " Encryption (" + (task.use_ecb_mode ? "ECB" : "CBC") + ")",
                operation_time, file_data.size());

            // Convert to bytes and save
            std::vector<uint8_t> encrypted_data = blocks_to_bytes(output_blocks);

            std::ofstream outfile(task.output_path, std::ios::binary);
            if (!outfile) {
                std::cerr << "Error: Cannot open output file " << task.output_path << std::endl;
                return false;
            }
            outfile.write(reinterpret_cast<const char*>(encrypted_data.data()), encrypted_data.size());
            outfile.close();

        }
        else {
            // Decryption - Input is already in blocks format
            input_blocks = bytes_to_blocks(file_data);

            if (task.implementation == "serial") {
                operation_name = "Serial 3DES";
                if (task.use_ecb_mode) {
                    operation_time = measure_execution_time([&]() {
                        serial_3des_ecb_decrypt(input_blocks, output_blocks, key1, key2, key3);
                        });
                }
                else {
                    operation_time = measure_execution_time([&]() {
                        serial_3des_cbc_decrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                        });
                }
            }
            else if (task.implementation == "openmp") {
                operation_name = "OpenMP 3DES";
                if (task.use_ecb_mode) {
                    operation_time = measure_execution_time([&]() {
                        openmp_3des_ecb_decrypt(input_blocks, output_blocks, key1, key2, key3);
                        });
                }
                else {
                    operation_time = measure_execution_time([&]() {
                        openmp_3des_cbc_decrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                        });
                }
            }
            else if (task.implementation == "pipeline") {
                operation_name = "Pipeline 3DES";
                if (task.use_ecb_mode) {
                    operation_time = measure_execution_time([&]() {
                        pipeline_3des_ecb_decrypt(input_blocks, output_blocks, key1, key2, key3);
                        });
                }
                else {
                    operation_time = measure_execution_time([&]() {
                        pipeline_3des_cbc_decrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                        });
                }
            }
            else if (task.implementation == "cuda") {
                operation_name = "CUDA 3DES";
                if (cuda_is_available()) {
                    cuda_init();
                    if (task.use_ecb_mode) {
                        operation_time = measure_execution_time([&]() {
                            cuda_3des_ecb_decrypt(input_blocks, output_blocks, key1, key2, key3);
                            });
                    }
                    else {
                        operation_time = measure_execution_time([&]() {
                            cuda_3des_cbc_decrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                            });
                    }
                    cuda_cleanup();
                }
                else {
                    operation_name = "OpenMP 3DES (fallback)";
                    if (task.use_ecb_mode) {
                        operation_time = measure_execution_time([&]() {
                            openmp_3des_ecb_decrypt(input_blocks, output_blocks, key1, key2, key3);
                            });
                    }
                    else {
                        operation_time = measure_execution_time([&]() {
                            openmp_3des_cbc_decrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                            });
                    }
                }
            }
            else if (task.implementation == "mpi") {
                operation_name = "MPI 3DES";
                MPI_Init(nullptr, nullptr);  // <<< Initialize MPI
                if (task.use_ecb_mode) {
                    operation_time = measure_execution_time([&]() {
                        mpi_3des_ecb_decrypt(input_blocks, output_blocks, key1, key2, key3);
                        });
                }
                else {
                    operation_time = measure_execution_time([&]() {
                        mpi_3des_cbc_decrypt(input_blocks, output_blocks, key1, key2, key3, iv);
                        });
                }
                MPI_Finalize();  // <<< Finalize MPI
            }


            // Display decryption performance
            display_performance(operation_name + " Decryption (" + (task.use_ecb_mode ? "ECB" : "CBC") + ")",
                operation_time, file_data.size());

            // Convert to bytes, remove padding, and save
            std::vector<uint8_t> decrypted_padded = blocks_to_bytes(output_blocks);
            std::vector<uint8_t> decrypted_data = remove_padding(decrypted_padded);

            std::ofstream outfile(task.output_path, std::ios::binary);
            if (!outfile) {
                std::cerr << "Error: Cannot open output file " << task.output_path << std::endl;
                return false;
            }
            outfile.write(reinterpret_cast<const char*>(decrypted_data.data()), decrypted_data.size());
            outfile.close();
        }

        std::cout << "Completed processing " << task.input_path << " -> " << task.output_path << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Error processing file " << task.input_path << ": " << e.what() << std::endl;
        return false;
    }
}

// Function to process multiple files using a thread pool
MultiBenchmarkResult process_multiple_files(const std::vector<FileTask>& tasks, int num_threads, bool is_benchmark = false) {
    // If thread count not specified, use number of hardware threads
    if (num_threads <= 0) {
        num_threads = std::thread::hardware_concurrency();
        // Ensure at least one thread
        if (num_threads <= 0) num_threads = 1;
    }

    if (!is_benchmark) {
        std::cout << "Starting batch processing with " << num_threads << " concurrent file processors..." << std::endl;
    }

    // Create task queue
    FileTaskQueue task_queue;

    // Calculate total bytes
    size_t total_bytes = 0;
    if (is_benchmark) {
        for (const auto& task : tasks) {
            std::ifstream file(task.input_path, std::ios::binary | std::ios::ate);
            if (file) {
                total_bytes += file.tellg();
                file.close();
            }
        }
    }

    // Add all tasks to queue
    for (const auto& task : tasks) {
        task_queue.push(task);
    }

    // Signal queue completion after all tasks are added
    task_queue.finish();

    // Create worker threads
    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    // Start timing
    auto start_time = std::chrono::high_resolution_clock::now();

    // Start worker threads
    std::atomic<int> successful_tasks(0);
    for (int i = 0; i < num_threads; i++) {
        threads.emplace_back([&task_queue, &successful_tasks]() {
            FileTask task;
            while (task_queue.pop(task)) {
                if (process_file(task)) {
                    successful_tasks++;
                }
            }
            });
    }

    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }

    // End timing
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration = end_time - start_time;

    // Prepare benchmark result
    MultiBenchmarkResult result;
    result.thread_count = num_threads;
    result.file_count = tasks.size();
    result.total_bytes = total_bytes;
    result.total_time = duration.count();
    result.throughput = (total_bytes / (1024.0 * 1024.0)) / duration.count();

    // Get implementation and mode from first task (assuming all tasks use the same)
    if (!tasks.empty()) {
        result.implementation = tasks[0].implementation;
        result.mode = tasks[0].use_ecb_mode ? "ECB" : "CBC";
        result.is_encryption = tasks[0].is_encryption;
    }

    if (!is_benchmark) {
        std::cout << "\nBatch processing completed in " << duration.count() << " seconds." << std::endl;
        std::cout << "Successfully processed " << successful_tasks << " out of " << tasks.size() << " files." << std::endl;
        if (total_bytes > 0) {
            double throughput = (total_bytes / (1024.0 * 1024.0)) / duration.count();
            std::cout << "Total data processed: " << std::fixed << std::setprecision(2)
                << (total_bytes / (1024.0 * 1024.0)) << " MB" << std::endl;
            std::cout << "Overall throughput: " << std::fixed << std::setprecision(2)
                << throughput << " MB/s" << std::endl;
        }
    }

    return result;
}



// Modify the main function to properly handle command line arguments
int main(int argc, char* argv[]) {
    // Create output directory if it doesn't exist
    _mkdir("output");
    _mkdir("data");
    _mkdir("results");

    std::cout << "===========================================\n";
    std::cout << "3DES Encryption/Decryption Tool\n";
    std::cout << "===========================================\n\n";

    // Check if command line arguments were provided
    bool interactive_mode = (argc <= 1);
    std::string mode_str;
    std::string impl_type;
    int num_threads = 0; // 0 means auto (use hardware concurrency)
    std::string input_path;
    bool is_encryption = true; // Default to encryption
    bool use_ecb_mode = false;

    if (!interactive_mode) {
        // Advanced command-line parsing:
        // Format: 3DesEncryption [e/d] [CBC/ECB] [implementation] [threads] [path]

        // Check if we have enough arguments
        if (argc < 6) {
            std::cout << "Error: Insufficient arguments\n";
            std::cout << "Usage: " << argv[0] << " [e/d] [CBC/ECB] [implementation] [threads] [path]\n";
            std::cout << "  [e/d]: e for encryption, d for decryption\n";
            std::cout << "  [CBC/ECB]: Encryption mode\n";
            std::cout << "  [implementation]: serial, openmp, pipeline, cuda\n";
            std::cout << "  [threads]: Number of threads (0 for auto)\n";
            std::cout << "  [path]: File or directory path\n";
            return 1;
        }

        // Parse operation type (encryption or decryption)
        std::string op_str = argv[1];
        std::transform(op_str.begin(), op_str.end(), op_str.begin(), ::tolower);
        if (op_str == "d" || op_str == "dec" || op_str == "decrypt" || op_str == "decryption") {
            is_encryption = false;
        }

        // Parse mode (CBC or ECB)
        mode_str = argv[2];
        std::transform(mode_str.begin(), mode_str.end(), mode_str.begin(), ::toupper);
        if (mode_str == "ECB") {
            use_ecb_mode = true;
        }
        else if (mode_str == "CBC") {
            use_ecb_mode = false;
        }
        else {
            std::cout << "Error: Invalid mode '" << mode_str << "'. Use CBC or ECB.\n";
            return 1;
        }

        // Parse implementation
        impl_type = argv[3];
        std::transform(impl_type.begin(), impl_type.end(), impl_type.begin(), ::tolower);
        if (impl_type != "serial" && impl_type != "openmp" && impl_type != "pipeline" && impl_type != "cuda" && impl_type != "mpi") {
            std::cout << "Error: Invalid implementation type '" << impl_type << "'. Use serial, openmp, pipeline, cuda, or mpi.\n";
            return 1;
        }

        // Check if CUDA is available when selected
        if (impl_type == "cuda" && !cuda_is_available()) {
            std::cout << "CUDA is not available on this system. Falling back to OpenMP.\n";
            impl_type = "openmp";
        }

        // Parse thread count
        try {
            num_threads = std::stoi(argv[4]);
            if (num_threads < 0) {
                std::cout << "Warning: Invalid thread count. Using auto-detection.\n";
                num_threads = 0;
            }
        }
        catch (...) {
            std::cout << "Warning: Invalid thread count format. Using auto-detection.\n";
            num_threads = 0;
        }

        // Parse input path
        input_path = argv[5];

        std::cout << "Running in command-line mode\n";
        std::cout << "Operation: " << (is_encryption ? "Encryption" : "Decryption") << "\n";
        std::cout << "Mode: " << mode_str << "\n";
        std::cout << "Implementation: " << impl_type << "\n";
        std::cout << "Threads: " << (num_threads == 0 ? "Auto" : std::to_string(num_threads)) << "\n";
        std::cout << "Path: " << input_path << "\n\n";

        // Check if the path is a file or directory
        bool is_directory = false;
        try {
            is_directory = std::filesystem::is_directory(input_path);
        }
        catch (...) {
            std::cout << "Error: Unable to access path: " << input_path << "\n";
            return 1;
        }

        if (is_directory) {
            // Process as directory (batch mode)
            std::string output_dir = "output";
            std::vector<FileTask> tasks;

            try {
                for (const auto& entry : std::filesystem::directory_iterator(input_path)) {
                    if (entry.is_regular_file()) {
                        std::string file_path = entry.path().string();
                        std::string filename = entry.path().filename().string();
                        std::string output_path = output_dir + "/" + std::string(is_encryption ? "enc_" : "dec_") + filename;

                        FileTask task;
                        task.input_path = file_path;
                        task.output_path = output_path;
                        task.is_encryption = is_encryption;
                        task.implementation = impl_type;
                        task.use_ecb_mode = use_ecb_mode;

                        // For decryption, need to find the corresponding key and IV files
                        if (!is_encryption) {
                            // If decrypting, look for key and IV files
                            std::string expected_enc_file = input_path + "/enc_" + std::string(filename);
                            std::string key_path = expected_enc_file + ".key";
                            std::string iv_path = expected_enc_file + ".iv";

                            // Check if files exist
                            std::ifstream key_test(key_path);
                            std::ifstream iv_test(iv_path);

                            if (key_test && iv_test) {
                                task.key_path = key_path;
                                task.iv_path = iv_path;
                            }
                            else {
                                // Try alternative locations
                                key_path = file_path + ".key";
                                iv_path = file_path + ".iv";

                                key_test = std::ifstream(key_path);
                                iv_test = std::ifstream(iv_path);

                                if (key_test && iv_test) {
                                    task.key_path = key_path;
                                    task.iv_path = iv_path;
                                }
                                else {
                                    std::cout << "Warning: Could not find key/IV files for " << file_path << std::endl;
                                    std::cout << "Searched in " << expected_enc_file << ".key/.iv and " << file_path << ".key/.iv" << std::endl;
                                    continue; // Skip this file
                                }
                            }
                        }

                        tasks.push_back(task);
                        std::cout << "Added task: " << file_path << " -> " << output_path << std::endl;
                    }
                }

                if (tasks.empty()) {
                    std::cout << "No valid files found for processing." << std::endl;
                    return 1;
                }

                std::cout << "Processing " << tasks.size() << " files in batch mode..." << std::endl;
                process_multiple_files(tasks, num_threads);
                std::cout << "Batch processing completed." << std::endl;

            }
            catch (const std::exception& e) {
                std::cerr << "Error processing directory: " << e.what() << std::endl;
                return 1;
            }
        }
        else {
            // Process as single file
            if (!std::filesystem::exists(input_path)) {
                std::cout << "Error: File not found: " << input_path << std::endl;
                return 1;
            }

            // Handle single file processing
            std::string output_path = std::string("output/") + (is_encryption ? "enc_" : "dec_") +
                std::filesystem::path(input_path).filename().string();

            FileTask task;
            task.input_path = input_path;
            task.output_path = output_path;
            task.is_encryption = is_encryption;
            task.implementation = impl_type;
            task.use_ecb_mode = use_ecb_mode;

            // For decryption, try to find key/IV files
            if (!is_encryption) {
                std::string key_path = input_path + ".key";
                std::string iv_path = input_path + ".iv";

                std::ifstream key_test(key_path);
                std::ifstream iv_test(iv_path);

                if (key_test && iv_test) {
                    task.key_path = key_path;
                    task.iv_path = iv_path;
                }
                else {
                    // Alternative location - assume we're decrypting a file that was previously encrypted
                    std::string base_filename = std::filesystem::path(input_path).filename().string();
                    if (base_filename.substr(0, 4) == "enc_") {
                        base_filename = base_filename.substr(4);
                    }
                    std::string input_dir = std::filesystem::path(input_path).parent_path().string();
                    if (input_dir.empty()) input_dir = ".";

                    key_path = input_dir + "/enc_" + base_filename + ".key";
                    iv_path = input_dir + "/enc_" + base_filename + ".iv";

                    key_test = std::ifstream(key_path);
                    iv_test = std::ifstream(iv_path);

                    if (key_test && iv_test) {
                        task.key_path = key_path;
                        task.iv_path = iv_path;
                    }
                    else {
                        std::cout << "Error: Could not find key/IV files for decryption." << std::endl;
                        std::cout << "Looked for: " << input_path << ".key/.iv and " << key_path << "/" << iv_path << std::endl;
                        return 1;
                    }
                }
            }

            std::cout << "Processing single file: " << input_path << " -> " << output_path << std::endl;
            process_file(task);
        }

        return 0;
    }
}