#include <stdio.h>
#include <fstream>
#include "utils.h"
#include "challenge7.h"

namespace challenge7 {

void RunChallenge() {
  std::ifstream file("7.txt");

  std::string line;
  std::vector<unsigned char> plaintext;
  while (std::getline(file, line)) {
    auto decoded = DecodeHexString(line);
    plaintext.insert(plaintext.end(), decoded.begin(), decoded.end());
  }

  std::string key = "YELLOW SUBMARINE";


  printf("\n----------\nEX7: AES ECB\n");
}

} // namespace challenge7