#pragma once
#include <vector>
#include <string>

namespace challenge1 {
  std::vector<unsigned char> Base64Decode(std::string const& encoded_string);
  std::string Base64Encode(std::vector<unsigned char> input);

  void RunChallenge();
}