#ifndef DES_UTILS_H
#define DES_UTILS_H

#include <vector>
#include <cstdint>
#include <string>
#include "des_impl.h" // Use our custom implementation

// Initialize DES key schedules from key bytes
void init_des_keys(DES_key_schedule& key1, DES_key_schedule& key2, DES_key_schedule& key3,
    const std::vector<uint8_t>& key_data);

// Pad data according to PKCS#7
std::vector<uint8_t> pad_data(const std::vector<uint8_t>& data);

// Remove PKCS#7 padding
std::vector<uint8_t> remove_padding(const std::vector<uint8_t>& padded_data);

// Convert bytes to 64-bit blocks
std::vector<uint64_t> bytes_to_blocks(const std::vector<uint8_t>& bytes);

// Convert 64-bit blocks to bytes
std::vector<uint8_t> blocks_to_bytes(const std::vector<uint64_t>& blocks);

// Generate random data of specified size
std::vector<uint8_t> generate_test_data(size_t size_bytes);

// Save data to file
void save_to_file(const std::string& filename, const std::vector<uint8_t>& data);

// Load data from file
std::vector<uint8_t> load_from_file(const std::string& filename);

#endif // DES_UTILS_H