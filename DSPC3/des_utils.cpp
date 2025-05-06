#define _CRT_SECURE_NO_WARNINGS
#include "des_utils.h"
#include <fstream>
#include <random>
#include <stdexcept>
#include <cstring>
#include <direct.h>  // For _mkdir

void init_des_keys(DES_key_schedule& key1, DES_key_schedule& key2, DES_key_schedule& key3,
    const std::vector<uint8_t>& key_data) {
    if (key_data.size() < 24) {
        throw std::runtime_error("Key data must be at least 24 bytes for 3DES");
    }

    DES_cblock key_block1, key_block2, key_block3;

    memcpy(key_block1.bytes, key_data.data(), 8);
    memcpy(key_block2.bytes, key_data.data() + 8, 8);
    memcpy(key_block3.bytes, key_data.data() + 16, 8);

    DES_set_key_checked(&key_block1, &key1);
    DES_set_key_checked(&key_block2, &key2);
    DES_set_key_checked(&key_block3, &key3);

}
std::vector<uint8_t> pad_data(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> padded_data = data;

    // PKCS#7 padding
    size_t padding_size = 8 - (data.size() % 8);
    if (padding_size == 0) {
        padding_size = 8; // Add a full block if already aligned
    }

    for (size_t i = 0; i < padding_size; i++) {
        padded_data.push_back(static_cast<uint8_t>(padding_size));
    }

    return padded_data;
}

std::vector<uint8_t> remove_padding(const std::vector<uint8_t>& padded_data) {
    if (padded_data.empty()) {
        return padded_data;
    }

    size_t padding_size = padded_data.back();

    if (padding_size > 8 || padding_size == 0 || padded_data.size() < padding_size) {
        // Invalid padding, return data as is
        return padded_data;
    }

    // Verify all padding bytes are correct
    for (size_t i = 1; i <= padding_size; i++) {
        if (padded_data[padded_data.size() - i] != padding_size) {
            // Invalid padding, return data as is
            return padded_data;
        }
    }

    // Remove padding
    return std::vector<uint8_t>(padded_data.begin(), padded_data.end() - padding_size);
}

std::vector<uint64_t> bytes_to_blocks(const std::vector<uint8_t>& bytes) {
    if (bytes.size() % 8 != 0) {
        throw std::runtime_error("Data size must be a multiple of 8 bytes");
    }

    std::vector<uint64_t> blocks(bytes.size() / 8);

    for (size_t i = 0; i < bytes.size() / 8; i++) {
        uint64_t block = 0;
        for (size_t j = 0; j < 8; j++) {
            block = (block << 8) | bytes[i * 8 + j];
        }
        blocks[i] = block;
    }

    return blocks;
}

std::vector<uint8_t> blocks_to_bytes(const std::vector<uint64_t>& blocks) {
    std::vector<uint8_t> bytes(blocks.size() * 8);

    for (size_t i = 0; i < blocks.size(); i++) {
        uint64_t block = blocks[i];
        for (size_t j = 0; j < 8; j++) {
            bytes[i * 8 + (7 - j)] = static_cast<uint8_t>(block & 0xFF);
            block >>= 8;
        }
    }

    return bytes;
}

std::vector<uint8_t> generate_test_data(size_t size_bytes) {
    std::vector<uint8_t> data(size_bytes);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < size_bytes; i++) {
        data[i] = static_cast<uint8_t>(dis(gen));
    }

    return data;
}

void save_to_file(const std::string& filename, const std::vector<uint8_t>& data) {
    // Create data directory if it doesn't exist
    _mkdir("data");

    std::string filepath = "data\\" + filename;
    std::ofstream file(filepath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Could not open file for writing: " + filepath);
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    if (!file) {
        throw std::runtime_error("Error writing to file: " + filepath);
    }
}

std::vector<uint8_t> load_from_file(const std::string& filename) {
    std::string filepath = "data\\" + filename;
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Could not open file for reading: " + filepath);
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(size);
    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
        throw std::runtime_error("Error reading from file: " + filepath);
    }

    return data;
}