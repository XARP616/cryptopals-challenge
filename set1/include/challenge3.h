#include <vector>
#pragma once

namespace challenge3 {
struct Score {
  int score;
  unsigned char character;
};

void RunChallenge();
// Returns the top three keys
std::vector<Score> BruteForceKey(const std::vector<unsigned char>& input);

} // namespace challenge3