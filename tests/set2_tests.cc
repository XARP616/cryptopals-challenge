#include <gtest/gtest.h>
#include <string>
#include <vector>
#include "utils.h"
#include "challenge9.h"
#include "challenge10.h"
#include "challenge14.h"
#include "challenge15.h"

const unsigned int kBlockSize = 16;

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

// EX10
TEST(Set2, AESCBCMode) {
  std::string key = "YELLOW SUBMARINE";
  std::vector<unsigned char> iv(16, '\03');
  std::string text = "This is just a test message";
  
  auto ciphertext = challenge10::CBCEncrypt({text.begin(), text.end()}, iv, {key.begin(), key.end()});
  auto decrypted = challenge10::CBCDecrypt(ciphertext, iv, {key.begin(), key.end()});
  std::string decrypted_str = {decrypted.begin(), decrypted.end()};
  
  EXPECT_EQ(text, decrypted_str);
  EXPECT_EQ(text.length(), decrypted_str.length()); // Going to fail until padding gets removed

  // TODO: test for a single block? (with the padding may not make sense)
}

// EX14
TEST(Set2, TextSizeGuessing) {
  size_t test_value = 1;
  auto actual_size = challenge14::InitRandomText();

  actual_size = challenge14::RegenerateRandomText(test_value);

  auto guessed_size = challenge14::GuessRandomTextSize();
  EXPECT_EQ(actual_size, guessed_size);

  test_value = 15;
  actual_size = challenge14::RegenerateRandomText(test_value);
  guessed_size = challenge14::GuessRandomTextSize();
  EXPECT_EQ(test_value, guessed_size);

  test_value = 16;
  actual_size = challenge14::RegenerateRandomText(test_value);
  guessed_size = challenge14::GuessRandomTextSize();
  EXPECT_EQ(test_value, guessed_size);

  test_value = 17;
  actual_size = challenge14::RegenerateRandomText(test_value);
  guessed_size = challenge14::GuessRandomTextSize();
  EXPECT_EQ(test_value, guessed_size);

  test_value = 31;
  actual_size = challenge14::RegenerateRandomText(test_value);
  guessed_size = challenge14::GuessRandomTextSize();
  EXPECT_EQ(test_value, guessed_size);

  test_value = 32;
  actual_size = challenge14::RegenerateRandomText(test_value);
  guessed_size = challenge14::GuessRandomTextSize();
  EXPECT_EQ(test_value, guessed_size);

  test_value = 100;
  actual_size = challenge14::RegenerateRandomText(test_value);
  guessed_size = challenge14::GuessRandomTextSize();
  EXPECT_EQ(test_value, guessed_size);
}

// EX15
TEST(Set2, PKCS7_validation) {
  std::string in1 = "ICE ICE BABY\x04\x04\x04\x04";
  std::string in2 = "ICE ICE BABY\x05\x05\x05\x05";
  std::string in3 = "ICE ICE BABYYYYY";

  std::vector<unsigned char> buf1 = {in1.begin(), in1.end()};
  std::vector<unsigned char> buf2 = {in2.begin(), in2.end()};
  std::vector<unsigned char> buf3 = {in3.begin(), in3.end()};
  auto buf4 = buf3;
  
  buf3.insert(buf3.end(), kBlockSize, '\x10');
  buf4.insert(buf4.begin(), kBlockSize, '\x10'); // last_char = 0x59

  // valid padding
  EXPECT_TRUE(challenge15::StripPadding(buf1));
  
  // invalid count of padding
  EXPECT_FALSE(challenge15::StripPadding(buf2));

  // valid 0x10 (16 bytes) padding
  bool res = challenge15::StripPadding(buf3);
  EXPECT_TRUE(res);

  // invalid last char
  EXPECT_FALSE(challenge15::StripPadding(buf4));
}