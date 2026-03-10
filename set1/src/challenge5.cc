#include <string>
#include "utils.h"
#include "challenge5.h"

namespace challenge5 {

std::string XORCipher(std::string input, std::string key) {
  std::string output = input;
  unsigned int characters_left = input.length();
  unsigned int index = 0;
  while(characters_left - index > 0) {
    auto xor_value = key[index % 3];
    output[index++] ^= xor_value;
  }

  return output;
}

void RunChallenge() {
  printf("\n----------\nEX5: Repeating-key XOR\n");

  std::string key = "ICE";
  std::string input = 
    "Burning 'em, if you ain't quick and nimble\n"
    "I go crazy when I hear a cymbal"
  ;

  auto ciphertext = XORCipher(input, key);
  for (unsigned int u = 0; u < input.length(); u++) {
    if (u == 37) printf("\n");
    printf("%02x", ciphertext[u]);
  } printf("\n");
}

} // namespace challenge5