#ifndef PERFORMANCE_H
#define PERFORMANCE_H

#include <vector>
#include <string>
#include "des_impl.h"

// Timing function
double get_time();

// Structure to hold performance results
struct PerformanceResult {
    std::string implementation;
    std::string mode;
    std::string operation;
    size_t data_size_mb;
    double execution_time;
    double throughput;
    double speedup;
};

// Multi-file benchmark result structure
struct MultiBenchmarkResult {
    int thread_count;
    size_t file_count;
    size_t total_bytes;
    double total_time;
    double throughput; // MB/s
    std::string implementation;
    std::string mode;
    bool is_encryption;
};

// Function to run multi-file benchmark
std::vector<MultiBenchmarkResult> run_multi_file_benchmark(const std::string& dir_path,
    const std::string& extension,
    bool is_encryption);

// Function to save multi-file benchmark results
void save_multi_benchmark_results(const std::string& filename,
    const std::vector<MultiBenchmarkResult>& results);

// Function to print multi-file benchmark results
void print_multi_benchmark_results(const std::vector<MultiBenchmarkResult>& results);

// Run all performance tests
std::vector<PerformanceResult> run_performance_tests(
    const std::vector<uint8_t>& test_data,
    const DES_key_schedule& key1,
    const DES_key_schedule& key2,
    const DES_key_schedule& key3,
    uint64_t iv);

// Save results to CSV
void save_results_to_csv(const std::string& filename,
    const std::vector<PerformanceResult>& results);

// Print results to console
void print_results(const std::vector<PerformanceResult>& results);

#endif // PERFORMANCE_H