#include <iostream>
#include <fstream>
#include <string>
#include "utils.h"
#include "challenge3.h"
#include "challenge4.h"

namespace challenge4 {

std::string ExploreFileAndBreak() {
  std::ifstream file("4.txt");
  if (!file.is_open()) {
    printf("[x] FAILED TO OPEN THE FILE\n");
    return "";
  }

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
      //printf(" ! Key 0x%02X with new best score (%u pts): ", score.character, best_score);
      //PrintCharVectorAsString(plaintext);
    }
  }

  return std::string(best_plaintext.begin(), best_plaintext.end());
}

void RunChallenge() {
  printf("\n----------\nEX4: Detect single-character XOR\n");
  
  auto best_plaintext = ExploreFileAndBreak();
  printf("> Best found plaintext: %s\n", best_plaintext.c_str());
  //PrintCharVectorAsString(best_plaintext);
}

} // namespace challenge4