#include <vector>
#include <string>
#include <format>

#pragma once

inline void PrintHexBuffer(std::vector<unsigned char> input) {
  for (unsigned int u = 0; u < input.size(); u++) {
    if (u % 16 == 0) printf("\n");
    printf("%02X ", input[u]);
  }
}

inline std::string EncodeHexString(std::vector<unsigned char> input) {
  std::string output;
  for (auto item : input) {
    output += std::format("{:02X}", item);
  }
  return output;
}

inline void PrintCharVectorAsString(std::vector<unsigned char> input) {
  for (auto character : input) {
    if (character < 0x20 || character > 0x7E) printf(".");
    else printf("%c", character);
  } printf("\n");
}

inline std::vector<unsigned char> DecodeHexString(std::string input) {
  std::vector<unsigned char> output;
  if (input.length() % 2 == 1) input += "0"; // if alignement is wrong

  for (unsigned int u = 0; u < input.length(); u+=2) {
    std::string tmp_str = {input[u], input[u+1]};
    char hex_input = std::stoi(tmp_str, nullptr, 16);
    output.push_back(hex_input);
  }

  //printf(" | Input STR:   %s\n", input.c_str());
  //printf(" | Decoded STR: %s\n", output.data());
  return output;
}

inline void XorCharVec(std::vector<unsigned char>& input, unsigned int xor_value) {
  for (auto& character : input) {
    character ^= xor_value;
  }
}

inline void XorBufferKey(std::vector<unsigned char>& input, const std::vector<unsigned char>& key) {
  if (key.size() == 0) return;
  for (std::size_t i = 0; auto& character : input) {
    character ^= key[i++ % key.size()];
  }
}