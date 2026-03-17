#include <cstring>
#include <vector>
#include <openssl/rand.h>
#include <random>
#include "utils.h"
#include "challenge11.h"
#include "challenge12.h"
#include "challenge14.h"

namespace challenge14 {

const size_t kRandomTextMinLen = 1;
const size_t kRandomTextMaxLen = 100;
const unsigned char kBlockSize = 16;
std::vector<unsigned char> random_text;

bool RegenerateRandomText(size_t size) {
  random_text.resize(size);
  int res = RAND_bytes(random_text.data(), random_text.size());
  if (res != 1) {
    random_text.resize(0);
    printf("[x] Error generating random text\n");
  }

  return random_text.size();
}

size_t InitRandomText(size_t text_len) {
  if (random_text.size()!= 0) return random_text.size();

  size_t random_text_len = rand() % kRandomTextMaxLen + kRandomTextMinLen;
  if (text_len == -1) RegenerateRandomText(random_text_len);
  else RegenerateRandomText(text_len);

  return random_text.size();
}

std::vector<unsigned char> TheC14Oracle(const std::vector<unsigned char>& input) {
  auto plaintext = input;

  if (random_text.size() == 0) InitRandomText();
  plaintext.insert(plaintext.begin(), random_text.begin(), random_text.end());
  //PrintHexBuffer(plaintext);
  return challenge12::TheNewEncryptionOracle(plaintext);
}

size_t GuessTheInitialBlocks() {
  // A = crafted input (AAA); C = ciphertext; C1 = first block of C; R = random text
  // When |A| = a, Ci = y; if |A| a+1 and Ci == x, Ci belongs to R
  // When |A| = a, Ci = y; if |A| a+1 and Ci != x, Ci does not belong to R

  size_t duplicated_blocks = 0;
  auto in1 = TheC14Oracle({'A'});
  auto in2 = TheC14Oracle({'B', 'B'});

  size_t max_size = (in1.size() > in2.size()) ? in2.size() : in1.size();

  std::span<const std::uint8_t> data1(in1);
  std::span<const std::uint8_t> data2(in2);
  for (size_t i = 0; i < max_size; i+=kBlockSize) { // TODO: bound check
    auto block_in1 = data1.subspan(i, kBlockSize);
    auto block_in2 = data2.subspan(i, kBlockSize);

    if (memcmp(block_in1.data(), block_in2.data(), kBlockSize) == 0) {
      duplicated_blocks++;
    } else break;
  }

  return duplicated_blocks;
}

size_t GuessRandomTextSize() {

  // 1. Check how many blocks are identical in the beginning
  //  [R8]    [R2 A6] [S8] ...
  //  [R8]    [R2 A6] [A8] ...
  //  [R8]    [R8]    [A8] ...
  //  [R2 A6] [A8]         ...
  auto initial_blocks = GuessTheInitialBlocks();
  auto min_size = initial_blocks * kBlockSize;
  //printf("%lu trailing blocks (min size: %lu bytes)\n", initial_blocks, initial_blocks * kBlockSize);

  std::vector<unsigned char> prev_block;
  for (size_t i = 0; i <= kBlockSize; i++) {
    auto in = std::vector<unsigned char>(i, 'A');
    auto ciphertext = TheC14Oracle(in);

    auto start_position = ciphertext.begin() + min_size;
    auto first_block = std::vector<unsigned char>(start_position, start_position + kBlockSize);

    if (first_block == prev_block) {
      return min_size + kBlockSize - i + 1;
    }
    prev_block = first_block;
  }

  return min_size; // the random text is perfectly aligned
}

void RemoveFirstBytes(std::vector<unsigned char>& input, size_t count) {
  input.erase(input.begin(), input.begin() + count);
}

std::vector<unsigned char> GetTargetCiphertextBlock(const std::vector<unsigned char>& test_input, unsigned int max_output_len, size_t remove_trailing) {
  auto target_output = TheC14Oracle(test_input);
  RemoveFirstBytes(target_output, remove_trailing);
  if (target_output.size() > max_output_len) target_output.resize(max_output_len);
  return target_output;
}

void BreakTheC14Oracle(size_t random_text_len) {
  printf("\n============= BREAKING ECB ================\n");
  std::vector<unsigned char> reconstructed_plaintext;

  auto initial_padding = std::vector<unsigned char>(kBlockSize - (random_text_len % kBlockSize), 'P');
  size_t padding_block_count = random_text_len / kBlockSize + 1;
  size_t initial_padding_size = padding_block_count * kBlockSize;
  printf("Padding block count: %lu\n", padding_block_count);
  PrintHexBuffer(initial_padding, "PADDING");

  unsigned int block_count = 1;
  bool remaining_characters = true;
  while (remaining_characters) {
    unsigned int dummy_bytes_count = kBlockSize * block_count - reconstructed_plaintext.size() - 1;
    
    auto dummy_buffer = std::vector<unsigned char>(dummy_bytes_count, 'A');
    dummy_buffer.insert(dummy_buffer.begin(), initial_padding.begin(), initial_padding.end());

    auto target_output = GetTargetCiphertextBlock(dummy_buffer, kBlockSize * block_count, initial_padding_size);
    
    dummy_buffer.insert(dummy_buffer.end(), reconstructed_plaintext.begin(), reconstructed_plaintext.end());
    dummy_buffer.push_back('?'); // guess token (this character will be replaced)

    // Brute force
    unsigned int character;
    for (character = 0x00; character <= 0xFF; character++) {
      unsigned char c = static_cast<unsigned char>(character);
      //printf("[%c = 0x%02X]\n", c, c);
      dummy_buffer.at(dummy_buffer.size() - 1) = c; // replace the last character
      auto ciphertext = TheC14Oracle(dummy_buffer);
      RemoveFirstBytes(ciphertext, initial_padding_size);

      // discard all but the first bytes
      if (ciphertext.size() > block_count * kBlockSize) ciphertext.resize(block_count * kBlockSize);

      // if we find a ciphertext that matches our input
      if (ciphertext == target_output) {
        reconstructed_plaintext.push_back(c);
        break;
      }
    }

    if (character > 0xFF) {
      remaining_characters = false;
      printf("[!] Failed to find an ASCII character. Message end.\n");
    }

    if (dummy_bytes_count == 0) block_count++;
    //PrintHexBuffer(reconstructed_plaintext, "PLAINTEXT SO FAR:");
  }

  PrintHexBuffer(reconstructed_plaintext, "FINAL PLAINTEXT");
}

void RunChallenge() {
  printf("\n----------\nEX14: Byte-at-a-time ECB decryption (Harder)\n");
  printf("Random text length: %lu\n", InitRandomText());

  std::string in = "This is my message";
  auto size = GuessRandomTextSize();
  printf("Guessed size: %lu\n", size);

  BreakTheC14Oracle(size);
}

}