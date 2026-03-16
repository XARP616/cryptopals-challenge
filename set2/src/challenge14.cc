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

size_t InitRandomText() {
  unsigned int random_text_len = rand() % kRandomTextMaxLen + kRandomTextMinLen;
  random_text.resize(random_text_len);
  int res = RAND_bytes(random_text.data(), random_text.size());
  if (res != 1) {
    printf("[x] Error generating random text\n");
    return 0;
  }

  return random_text_len;
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
  printf("%lu trailing blocks (min size: %lu bytes)\n", initial_blocks, initial_blocks * kBlockSize);

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

void RunChallenge() {
  printf("\n----------\nEX14: Byte-at-a-time ECB decryption (Harder)\n");
  printf("Random text length: %lu\n", InitRandomText());

  std::string in = "This is my message";
  auto size = GuessRandomTextSize();
  printf("Guessed size: %lu\n", size);

  
}

}