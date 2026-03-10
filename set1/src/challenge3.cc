#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <limits.h>
#include "challenge3.h"
#include "utils.h"

namespace challenge3 {

// ETAOIN -- most common characters in English
std::unordered_map<unsigned char, unsigned int> scores = {
  {' ', 13},
  {'E', 12}, {'e', 12}, {'T', 11}, {'t', 11}, {'A', 10}, {'a', 10},
  {'O', 9}, {'o', 9}, {'I', 8}, {'i', 8}, {'N', 7}, {'n', 7},
  {'S', 6}, {'s', 6}, {'H', 5}, {'h', 5}, {'R',4 }, {'r', 4},
  {'D', 3}, {'d', 3}, {'L', 2}, {'l', 2}, {'U', 1}, {'u', 1}
};

const int kPenalty = 2;

// Scores a potential plaintext based on ETAOIN
int ScoreString(const std::vector<unsigned char>& input) {
  int score = 0;
  for (auto& character : input) {
    if (scores.contains(character)) score += scores[character];
    else if (character < 0x20 || character > 0x7F) score -= kPenalty;
  }
  return score;
}

std::vector<Score> BruteForceKey(const std::vector<unsigned char>& input) {
  Score top1{0,0}, top2{0,0}, top3{0,0};

  for (unsigned int xor_value = 0; xor_value <= UCHAR_MAX ; xor_value++) {
    auto key_char = static_cast<unsigned char>(xor_value);
    auto tested_string = input; // copy
    XorBufferKey(tested_string, {key_char});

    auto score = ScoreString(tested_string);
    // printf("Score for %c: %u\n", xor_value, score);

    if (score > top1.score) {
      top3 = top2;
      top2 = top1;
      top1 = {score, key_char};
    } else if (score > top2.score) {
      top3 = top2;
      top2 = {score, key_char};
    } else if (score > top3.score) {
      top3 = {score, key_char};
    }
  }

  //printf(" | TOP1 key: {%c (%u pts)} / TOP2 key: {%c (%u pts)} / TOP3 key: {%c (%u pts)}\n", 
  //  top1.character, top1.score, top2.character, top2.score, top3.character, top3.score);
  return {top1, top2, top3};
}

void RunChallenge() {
  printf("\n----------\nEX3: Single-byte XOR cipher\n");
  std::string input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
  auto decoded_input = DecodeHexString(input);
  auto plaintext = decoded_input;
  auto score = BruteForceKey(plaintext)[0];
  XorCharVec(plaintext, score.character);

  // pretty print
  printf(" | Ciphertext: ");
  PrintCharVectorAsString(decoded_input);
  printf(" | Best score key: %c (%u pts)\n", score.character, score.score);
  printf("> Plaintext: ");
  PrintCharVectorAsString(plaintext);
}

} // namespace challenge3