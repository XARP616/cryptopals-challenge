#include <iostream>
#include <fstream>
#include <string>
#include "utils.h"
#include "challenge3.h"
#include "challenge4.h"

namespace challenge4 {

void RunChallenge() {
  printf("\n----------\nEX4: Detect single-character XOR\n");
  std::ifstream file("4.txt");

  unsigned int best_score = 0;
  std::vector<unsigned char> best_plaintext;
  std::string line;
  while (std::getline(file, line)) {
    auto decoded = DecodeHexString(line);
    auto plaintext = decoded;
    auto score = challenge3::BruteForceKey(plaintext)[0];
    XorCharVec(plaintext, score.character);
    
    if (score.score > best_score) {
      best_score = score.score;
      best_plaintext = plaintext;
      printf(" ! Key 0x%02X with new best score (%u pts): ", score.character, best_score);
      PrintCharVectorAsString(plaintext);
    }
  }
  printf("> Best found plaintext: ");
  PrintCharVectorAsString(best_plaintext);
}

} // namespace challenge4