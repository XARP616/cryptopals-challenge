#include <string>
#include "utils.h"
#include "challenge9.h"

namespace challenge9 {

inline void PKCS7Padding(std::vector<unsigned char>& input, size_t block_length) {
  size_t pad = block_length - (input.size() % block_length);
  input.insert(input.end(), pad, static_cast<unsigned char>(pad));
}

void RunChallenge() {
  printf("\n----------\nEX9: PKCS#7 Padding\n");

  std::string input_str = "YELLOW SUBMARINE";
  std::vector<unsigned char> input = {input_str.begin(), input_str.end()};

  auto old_size = input.size();
  PKCS7Padding(input, 20);
  
  printf(" Size %lu -> %lu\n", old_size, input.size());
  printf("> Buffer: ");
  PrintHexBuffer(input);
}

} // namespace challenge9