#include <iostream>
#include "challenge2.h"
#include "utils.h"

namespace challenge2 {

std::vector<unsigned char> FixedXOR(std::vector<unsigned char> str1, std::vector<unsigned char> str2) {
  std::vector<unsigned char> output(str1.size());
  if (str2.size() != str2.size()) return output;

  for (unsigned int i = 0; i < str1.size(); i++) {
    output[i] = str1[i] ^ str2[i];
  }

  return output;
}

void RunChallenge() {
  printf("\n----------\n");
  printf("EX2: FIXED XOR\n");
  std::string str1 = "1c0111001f010100061a024b53535009181c";
  std::string str2 = "686974207468652062756c6c277320657965";
  std::cout << " | String A: " << str1 << std::endl;
  std::cout << " | String B: " << str2 << std::endl;

  auto res = FixedXOR(DecodeHexString(str1), DecodeHexString(str2));
  std::cout << "> XOR result: " << std::string(res.begin(), res.end()) << std::endl;
  // std::cout << EncodeHexString(res) << std::endl;


}

} // namespace challenge2