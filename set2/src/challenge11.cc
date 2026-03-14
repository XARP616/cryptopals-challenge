#include <openssl/rand.h>
#include <cstdlib>
#include <set>
#include "utils.h"
#include "challenge7.h"
#include "challenge10.h"
#include "challenge11.h"

namespace challenge11 {

const unsigned int kBlockSizeBytes = 16;
// CSPRNG: https://docs.openssl.org/3.0/man3/RAND_bytes/#synopsis
// Returns a cryptographically secure 16 byte random number
std::vector<unsigned char> RandomAESKey() {
  std::vector<unsigned char> key(kBlockSizeBytes);

  int res = RAND_bytes(key.data(), key.size());
  if (res != 1) printf("[x] Error generating key\n");

  return key;
}

void GuessEncryptionMode(std::vector<unsigned char> input) {
  std::set<std::vector<unsigned char>> blocks;
  for (auto block_start = input.begin(); block_start < input.end(); block_start += kBlockSizeBytes) {
    auto block_end = block_start + kBlockSizeBytes;
    std::vector<unsigned char> current_block(block_start, block_end);

    if (blocks.contains(current_block)) PrintHexBuffer(current_block, "Probably an ECB block:");
    else {
      PrintHexBuffer(current_block, "Probably a CBC block:");
      blocks.insert(current_block);
    }
  }
}

void EncryptionOracle(std::vector<unsigned char> plaintext) {
  std::vector<unsigned char> padding_before;
  std::vector<unsigned char> padding_after;
    
  for (unsigned int i = 0; i < rand() % 6 + 5; i++) padding_before.push_back(rand());
  for (unsigned int i = 0; i < rand() % 6 + 5; i++) padding_after.push_back(rand());
  plaintext.insert(plaintext.begin(), padding_before.begin(), padding_before.end());
  plaintext.insert(plaintext.end(), padding_after.begin(), padding_after.end());

  std::vector<unsigned char> ciphertext;
  auto key = RandomAESKey();
  for (auto current_block = plaintext.begin(); current_block < plaintext.end(); current_block += kBlockSizeBytes) {
    auto block_end = current_block + kBlockSizeBytes;
    std::vector<unsigned char> block;
    if (rand() % 2 == 0) {
      auto iv = RandomAESKey();
      block = challenge10::CBCEncrypt({current_block, block_end}, iv, key, false);
    } else {
      block = challenge7::EncryptAesEcb({current_block, block_end}, key, false);
    }
    ciphertext.insert(ciphertext.end(), block.begin(), block.end());
  }

  GuessEncryptionMode(ciphertext);
}

void RunChallenge() {
  printf("\n----------\nEX11: ECB/CBC Oracle\n");

  auto input = std::vector<unsigned char>(160, 'A');
  EncryptionOracle(input);
}

} // namespace challenge11