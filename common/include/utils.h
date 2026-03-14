#include <vector>
#include <string>
#include <format>
#include <fstream>

#pragma once

inline void PrintHexBuffer(const std::vector<unsigned char>& input, std::string description = "") {
  std::string formatted_line;

  if (description.length() != 0) printf("%s", description.c_str());
  printf("\n 0           4            8           C            _ ASCII ________\n");

  unsigned int u;
  for (u = 0; u < input.size(); u++) {
    if (u > 0) {
      if (u % 16 == 0) {
        printf("  %s\n", formatted_line.c_str());
        formatted_line.clear();
      } else if (u % 8 == 0) printf(" ");
    }

    unsigned char character;
    if (input[u] < 0x20 || input[u] > 0x7E) character = '.';
    else character = input[u];
    
    printf("%02X ", input[u]);
    formatted_line += std::format("{}", static_cast<char>(character));

  } 
  
  if (u % 16 > 0) {
    // add missing spaces
    std::string final_line;
    int already = (u % 16) * 3;
    for (unsigned int i = already; i < 50; i++) {
      final_line += " ";
    }

    final_line += formatted_line;
    printf(" %s\n", final_line.c_str());
  } else if (u % 16 == 0) printf("  %s\n", formatted_line.c_str());

  printf("\n");
}

inline void PrintCharVectorAsString(const std::vector<unsigned char>& input) {
  for (auto character : input) {
    if (character < 0x20 || character > 0x7E) printf(".");
    else printf("%c", character);
  } printf("\n");
}

inline std::string EncodeHexString(const std::vector<unsigned char>& input, bool uppercase = false) {
  std::string output;
  if (uppercase) {
    for (auto& item : input) output += std::format("{:02X}", item);
  } else {
    for (auto& item : input) output += std::format("{:02x}", item);
  }

  return output;
}

inline std::vector<unsigned char> DecodeHexString(const std::string& input) {
  std::vector<unsigned char> output;

  if (input.length() % 2 == 1) {
    printf("[x] Invalid input length: %lu\n", input.length());
    return output;
  }

  for (unsigned int u = 0; u < input.length(); u+=2) {
    std::string formatted_char = {input[u], input[u+1]};
    char hex_input = std::stoi(formatted_char, nullptr, 16);
    output.push_back(hex_input);
  }

  //printf(" | Input STR:   %s\n", input.c_str());
  //printf(" | Decoded STR: %s\n", output.data());
  return output;
}

// Reads all the lines of a file and concatenates them into a single string
inline bool ParseFile(const std::string input_file, std::string& output) {
  std::ifstream file(input_file);
  if (!file.is_open()) return false;

  std::string line;
  while (std::getline(file, line)) {
    output += line;
  }

  return true;
}

inline void XorCharVec(std::vector<unsigned char>& input, unsigned int xor_value) {
  for (auto& character : input) {
    character ^= xor_value;
  }
}

inline void XorBufferKey(std::vector<unsigned char>& input, const std::vector<unsigned char>& key) {
  if (key.size() == 0) return;
  for (size_t i = 0; auto& character : input) {
    character ^= key[i++ % key.size()];
  }
}

// Takes two buffers and XORs them. The result is written on in1
inline void XorBuffer(unsigned char* in1, const unsigned char* in2, size_t size) {
  for (size_t i = 0; i < size; i++) in1[i] ^= in2[i];
}