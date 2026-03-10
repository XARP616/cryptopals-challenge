#include <iostream>
#include <string>
#include <cstdint>
#include <format>

#include "challenge1.h"
#include "utils.h"

namespace challenge1 {

static std::string kBase64Table =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "abcdefghijklmnopqrstuvwxyz"
  "0123456789+/"
;

char ToBase64Value(unsigned char byte) {
  if (byte > 63) return 0;
  return kBase64Table[byte];
}

// https://stackoverflow.com/questions/180947/base64-decode-snippet-in-c
static inline bool IsBase64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}

const uint32_t kLast6BitsMask = 0x3F; // 0011 1111

// EX1
// Encodes a string to Base64.
//  * Each 6 bits have a representation in the Base64 table.
//  * The function iterates over 3 byte groups and 4 masks
// Sources:
//  https://rahuulmiishra.medium.com/how-does-base64-work-9cbf8bd743a9
//  https://www.lifewire.com/base64-encoding-overview-1166412
//  https://cyberchef.org/#recipe=From_Hex('Auto')To_Base64('A-Za-z0-9%2B/%3D')
//  https://beetwise.com/
std::string Base64Encode(std::vector<unsigned char> input) {
  std::string output;

  // First round: groups of three
  unsigned int fixed_length = input.size() - (input.size() % 3);
  for (unsigned int i = 0; i < fixed_length; i+=3) {
    // add all numbers in a single variable
    uint32_t byte_group = input[i] << 16 | input[i+1] << 8 | input[i+2];

    // work with 6 bit groups off the previous
    output += ToBase64Value((byte_group >> 18) & kLast6BitsMask); // extract highest 6 bits
    output += ToBase64Value((byte_group >> 12) & kLast6BitsMask); // down to
    output += ToBase64Value((byte_group >> 6) & kLast6BitsMask);
    output += ToBase64Value(byte_group & kLast6BitsMask);         // last six bits
  }

  // Second round: one char remaining
  if (input.size() % 3 == 1) {
    auto alignement_padding = 4;
    uint32_t byte_group = 0 | input[input.size() - 1] << alignement_padding;
    output += ToBase64Value((byte_group >> 6) & kLast6BitsMask);
    output += ToBase64Value(byte_group & kLast6BitsMask);
    output += "==";
  }

  if (input.size() % 3 == 2) {
    auto alignement_padding = 2;
    uint32_t byte_group = 0 | input[input.size() - 2] << 10 | input[input.size() - 1] << alignement_padding;
    output += ToBase64Value((byte_group >> 12) & kLast6BitsMask);
    output += ToBase64Value((byte_group >> 6) & kLast6BitsMask);
    output += ToBase64Value(byte_group & kLast6BitsMask);
    output += "=";
  }

  return output;
}

// https://stackoverflow.com/questions/180947/base64-decode-snippet-in-c
std::vector<unsigned char> Base64Decode(std::string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::vector<unsigned char> ret;

  while (in_len-- && ( encoded_string[in_] != '=') && IsBase64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i == 4) {
      for (i = 0; i < 4; i++)
        char_array_4[i] = kBase64Table.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret.push_back(char_array_3[i]);
      i = 0;
    }
  }

  if (i) {
    for (j = i; j < 4; j++)
      char_array_4[j] = 0;

    for (j = 0; j < 4; j++)
      char_array_4[j] = kBase64Table.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
  }

  return ret;
}



void RunChallenge() {
  // ex1: BASE64
  printf("--------\n");
  printf("EX1: CONVERT HEX TO BASE64\n");
  std::string input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
  auto output = Base64Encode(DecodeHexString(input));
  std::cout << " | Encoded: " << input << std::endl;
  std::cout << "> Decoded: " << output << std::endl;
}

} // namespace challenge