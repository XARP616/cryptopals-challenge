#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "utils.h"
#include "challenge1.h"
#include "challenge2.h"
#include "challenge3.h"
#include "challenge4.h"
#include "challenge5.h"
#include "challenge6.h"

TEST(Set1, Base64Encoding) {
  std::string input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
  std::string expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

  auto out = challenge1::Base64Encode(DecodeHexString(input));
  EXPECT_EQ(out, expected_output) << "Input did not match the expected base64 output";
}

TEST(Set1, FixedXOR) {
  std::string input1 = "1c0111001f010100061a024b53535009181c";
  std::string input2 = "686974207468652062756c6c277320657965";
  std::vector<unsigned char> expected = {0x74,0x68,0x65,0x20,0x6b,0x69,0x64,0x20,0x64,0x6f,0x6e,0x27,0x74,0x20,0x70,0x6c,0x61,0x79};

  auto output = challenge2::FixedXOR(
    DecodeHexString(input1), 
    DecodeHexString(input2)
  );

  EXPECT_EQ(output, expected);
}

TEST(Set1, VignereCipher) {
  std::string input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
  char expected_key = 'X';

  auto scores = challenge3::BruteForceKey(DecodeHexString(input));
  EXPECT_EQ(scores[0].character, expected_key);
}

TEST(Set1, MultipleVignereCipher) {
  std::string expected_output = "Now that the party is jumping\n";
  auto output = challenge4::ExploreFileAndBreak();

  EXPECT_EQ(output, expected_output);
}