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
#include "challenge7.h"
#include "challenge8.h"

// EX1
TEST(Set1, Base64Encoding) {
  std::string input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
  std::string expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

  auto out = challenge1::Base64Encode(DecodeHexString(input));
  EXPECT_EQ(out, expected_output) << "Input did not match the expected base64 output";
}

// EX2
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

// EX3
TEST(Set1, SingleXORCipher) {
  std::string input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
  char expected_key = 'X';

  auto scores = challenge3::BruteForceKey(DecodeHexString(input));
  EXPECT_EQ(scores[0].character, expected_key) << "Wrong key retrieved";
}

// EX4
TEST(Set1, MultipleSingleXORCipher) {
  std::string expected_output = "Now that the party is jumping\n";
  auto output = challenge4::ExploreFileAndBreak();

  EXPECT_EQ(output, expected_output) << "Plaintext mismatches";
}

// EX5
TEST(Set1, VigenereCipher) {
  std::string input = 
    "Burning 'em, if you ain't quick and nimble\n"
    "I go crazy when I hear a cymbal"
  ;
  std::string key = "ICE";
  std::string expected_output = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

  auto ciphertext = challenge5::XORCipher(input, key);
  auto output = std::vector<unsigned char>(ciphertext.begin(), ciphertext.end());
  EXPECT_EQ(EncodeHexString(output), expected_output) << "Wrong resulting ciphertext";
}

// EX6
TEST(Set1, HammingDistance) {
  std::string str1 = "this is a test";
  std::string str2 = "wokka wokka!!!";

  auto h_distance = challenge6::CalculateHammingDistanceBits(
    (unsigned char*) str1.data(),
    (unsigned char*) str2.data(),
    str1.length()
  );

  EXPECT_EQ(h_distance, 37) << "Hamming distance mismatch";
}

// EX6
TEST(Set1, BreakingVigenere) {
  std::string input;
  if (!ParseFile("6.txt", input)) FAIL() << "Failed to open the input file";

  auto ciphertext = challenge1::Base64Decode(input);
  auto key = challenge6::BreakRepeartingXOR(ciphertext);
  
  std::string expected_key = "Terminator X: Bring the noise";
  std::string tested_key = {key.begin(), key.end()};
  EXPECT_EQ(tested_key, expected_key) << "Key mismatch";
}

// EX7
TEST(Set1, CryptoAES_ECB) {
  std::string input;
  std::string key = "YELLOW SUBMARINE";
  if (!ParseFile("7.txt", input)) FAIL() << "Failed to open the input file";

  auto decoded = challenge1::Base64Decode(input);
  auto plaintext = challenge7::DecryptAesEcb(decoded, {key.begin(), key.end()});
  auto ciphertext = challenge7::EncryptAesEcb(plaintext, {key.begin(), key.end()});

  std::string expected_plaintext = "I'm back and I'm ringin' the bell";
  auto plaintext_extract = std::string(plaintext.begin(), plaintext.begin() + expected_plaintext.length());
  EXPECT_EQ(plaintext_extract, expected_plaintext) << "The plaintext is not correct";
  EXPECT_EQ(ciphertext, decoded) << "The ciphertext does not match the original";
}

// EX8
TEST(Set1, DetectECB) {
  std::string expected_result = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
  auto file = std::ifstream("8.txt");
  auto result = challenge8::DetectAesEcb(file);
  EXPECT_EQ(result, expected_result);
}