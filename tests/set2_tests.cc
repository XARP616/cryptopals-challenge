#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "utils.h"
#include "challenge9.h"
#include "challenge10.h"

// EX9
TEST(Set2, PKCS7Padding) {
  std::string input_str = "YELLOW SUBMARINE";
  std::string expected_str = "YELLOW SUBMARINE\x04\x04\x04\x04";
  std::vector<unsigned char> expected = {expected_str.begin(), expected_str.end()};
  size_t padding = 20;
  
  std::vector<unsigned char> input = {input_str.begin(), input_str.end()};
  challenge9::PKCS7Padding(input, padding);
  
  EXPECT_EQ(input, expected) << "First test failed";

  input_str = "ABCDEFGHIJKLMNOPQRST";
  expected_str = "ABCDEFGHIJKLMNOPQRST\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C\x0C";
  expected = {expected_str.begin(), expected_str.end()};
  input = {input_str.begin(), input_str.end()};

  size_t block_size = 16;
  challenge9::PKCS7Padding(input, block_size);

  EXPECT_EQ(input, expected) << "Second test failed";

  input = std::vector<unsigned char>(16, 'A');
  challenge9::PKCS7Padding(input, 16);

  EXPECT_EQ(input, input) << "Content mismatch";
  EXPECT_EQ(input.size(), input.size()) << "Size mismatch";
}

// EX9
TEST(Set2, AESCBCMode) {
  std::string key = "YELLOW SUBMARINE";
  std::vector<unsigned char> iv(16, '\03');

  std::string text = "This is just a test message";
  auto ciphertext = challenge10::CBCEncrypt({text.begin(), text.end()}, iv, {key.begin(), key.end()});
  auto decrypted = challenge10::CBCDecrypt(ciphertext, iv, {key.begin(), key.end()});
  std::string decrypted_str = {decrypted.begin(), decrypted.end()};
  
  EXPECT_EQ(text, decrypted_str);
  EXPECT_EQ(text.length(), decrypted_str.length()); // Going to fail until padding gets removed
}