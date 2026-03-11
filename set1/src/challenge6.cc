#include <fstream>
#include <vector>
#include <bit>
#include "utils.h"
#include "challenge1.h"
#include "challenge3.h"
#include "challenge6.h"

namespace challenge6 {

// Edit distance = hamming distance
unsigned int CalculateHammingDistanceBits(unsigned char* buffer1, unsigned char* buffer2, std::size_t input_size) {
  // 1. XOR both bytes (bit is set if the inputs are not equal)
  // 2. Count how many set bits result (x86 single instruction op)
  unsigned int distance = 0;
  for (std::size_t i = 0; i < input_size; i++) {
    unsigned char character = buffer1[i] ^ buffer2[i];
    distance += std::popcount(character);
  }

  return distance;
}

unsigned int MostLikelyKeySize(std::vector<unsigned char>& ciphertext) {
  double best_distance = 20.0;
  unsigned int best_key_size = 2;
  
  for (unsigned int key_size = 2; key_size <= 30; key_size++) {  
    unsigned int blocks = 16; //ciphertext.size() / key_size;
    double norm_distance = 0;
    unsigned int offset = 0;
    //printf(" | Blocks: %u, ciphertext size: %lu, key size: %u\n", blocks, ciphertext.size(), key_size);
    
    for (unsigned int i = 0; i < blocks - 1; i++) {
      auto h_distance = CalculateHammingDistanceBits(
        ciphertext.data() + offset,
        ciphertext.data() + offset + key_size,
        key_size
      );

      offset += key_size;
      norm_distance += static_cast<double>(h_distance) / key_size;
    }

    norm_distance /= blocks - 1;
    
    //printf(" | Distance: %.2f\n", norm_distance);
    if (norm_distance < best_distance) {
      best_distance = norm_distance;
      best_key_size = key_size;
    }
  }

  printf(" | Most likely hamming distance: %.2f\n", best_distance);
  printf(" | Most likely key size: %u\n", best_key_size);
  return best_key_size;
}

void BreakRepeartingXOR(std::vector<unsigned char>& ciphertext) {
  auto key_size = MostLikelyKeySize(ciphertext);

  // Round robin split
  std::vector<std::vector<unsigned char>> groups(key_size);
  for (std::size_t i = 0; auto c : ciphertext) {
    groups[i++ % key_size].push_back(c);
  }

  auto possible_keys = std::vector<std::string>(key_size);
  std::vector<unsigned char> key;
  for (std::vector<unsigned char>& group : groups) {
    auto scores = challenge3::BruteForceKey(group);
    key.push_back(scores[0].character);
  }
  printf(" | Most probable key: "); PrintCharVectorAsString(key);

  auto plaintext = ciphertext;
  XorBufferKey(plaintext, key);
  printf("> Plaintext:\n");
  PrintCharVectorAsString(plaintext);
}

void RunChallenge() {
  printf("\n----------\nEX6: Breaking a reapeating XOR key\n");
  std::ifstream file("6.txt");
  if (!file.is_open()) printf("[x] FAILED TO OPEN THE FILE\n");

  std::string input, line;
  while (std::getline(file, line)) {
    input += line;
  }

  // TODO: mover a los tests
  {
    // 1. Calculate the Hamming Distance
    std::string str1 = "this is a test";
    std::string str2 = "wokka wokka!!!";
    auto h_distance = CalculateHammingDistanceBits(
      (unsigned char*) str1.data(),
      (unsigned char*) str2.data(),
      str1.length()
    );

    if (h_distance != 37) { printf("Failed to check hamming distance\n"); return;}
    printf("> Test hamming distance checks out: %u\n", h_distance);
  }

  auto decoded = challenge1::Base64Decode(input);
  // printf(" | Input: ");PrintCharVectorAsString(decoded);
  BreakRepeartingXOR(decoded);

}

} // namespace challenge6