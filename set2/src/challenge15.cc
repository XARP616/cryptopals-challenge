#include <vector>
#include <string>
#include <cstring>
#include "utils.h"
#include "challenge15.h"

namespace challenge15 {

const unsigned int kBlockSize = 16;

// Returns how many bytes of padding contains the input.
// If the padding is invalid, the number returned will be
// equal to the input size.
size_t ValidatePadding(const std::vector<unsigned char>& input) {
  if (input.size() % kBlockSize != 0) return input.size();
  
  unsigned char count;
  char last_char = input[input.size() - 1];
  if (last_char == 0) count = static_cast<unsigned char>(kBlockSize);
  else count = last_char;

  if (last_char >= kBlockSize || count >= input.size()) return input.size(); // invalid last character
  
  auto padding_start = input.size() - count;

  bool valid = true;
  for (unsigned int i = padding_start; i < input.size(); i++) {
    if (input.at(i) != last_char) valid = false;
  }

  if (!valid) count = 0;
  return input.size() - count; 
}

bool StripPadding(std::vector<unsigned char>& input) {
  auto shrink_to = ValidatePadding(input);

  if (shrink_to == input.size()) return false; // Invalid padding
  input.resize(shrink_to);
  return true;
}

void RunChallenge() {
  printf("\n----------\nEX15: PKCS#7 padding validation\n");
  std::string in1 = "ICE ICE BABY\x04\x04\x04\x04";
  std::string in2 = "ICE ICE BABY\x05\x05\x05\x05";

  std::vector<unsigned char> buf1 = {in1.begin(), in1.end()};
  std::vector<unsigned char> buf2 = {in2.begin(), in2.end()};

  PrintHexBuffer(buf1, "BUFFER 1");
  if (StripPadding(buf1)) printf("Buf1 has a valid padding\n");
  else printf("Buf1 does not have a valid padding\n");
  PrintHexBuffer(buf1, "BUFFER 1");
  
  PrintHexBuffer(buf2, "BUFFER 2");
  if (StripPadding(buf2)) printf("Buf2 has a valid padding\n");
  else printf("Buf2 does not have a valid padding\n");
}

}