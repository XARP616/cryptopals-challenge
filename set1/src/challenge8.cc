#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <string>
#include "utils.h"
#include "challenge8.h"

namespace challenge8 {

const std::size_t kBlockSize = 16;

unsigned int ScoreString(const std::vector<unsigned char>& input) {
  std::span<const std::uint8_t> data(input); // create a view from the data

  unsigned int count = 0;
  for (std::size_t i = 0; i < input.size(); i += kBlockSize)  {
    auto block1 = data.subspan(i, kBlockSize);

    // `j = i + kBlockSize` to avoid repeated comparisons
    for (std::size_t j = i + kBlockSize; j < input.size(); j += kBlockSize) { 
      auto block2 = data.subspan(j, kBlockSize);
      if (memcmp(block1.data(), block2.data(), kBlockSize) == 0) count++;
    }
  }
  return count;
}

std::string DetectAesEcb(std::ifstream& file) {
  if (!file.is_open()) {
    printf("[x] FAILED TO OPEN THE FILE\n");
    return "";
  }

  unsigned int best_score = 0;
  std::string best_line;
  std::string line;

  while(std::getline(file, line)) {
    auto score = ScoreString(DecodeHexString(line));
    if (score > best_score) {
      best_score = score;
      best_line = line;
    }
  }

  return best_line;
}

void RunChallenge() {
  printf("\n----------\nEX8: Detect ECB\n");

  auto file = std::ifstream("8.txt");
  auto ecb_line = DetectAesEcb(file);
  printf("Best score line: %s\n", ecb_line.c_str());
}

} // namespace challenge8