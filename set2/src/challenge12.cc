#include <vector>
#include "utils.h"
#include "challenge1.h"
#include "challenge7.h"
#include "challenge11.h"
#include "challenge12.h"

namespace challenge12 {

std::vector<unsigned char> key;

std::vector<unsigned char> TheNewEncryptionOracle(std::vector<unsigned char> plaintext) {
  std::string prepend = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
  auto decoded = challenge1::Base64Decode(prepend);
  plaintext.insert(plaintext.end(), decoded.begin(), decoded.end());

  PrintHexBuffer(plaintext, "PLAINTEXT");
  return challenge7::EncryptAesEcb(plaintext, key);
}

// Guesses the block size by evaluating how often the ciphertext length changes
unsigned int GuessBlockSize() {
  unsigned int 
    block_size = 0, 
    potential_block_size = 0, 
    prev_ctxt_size = 0, 
    max_block_size = 80;

  for (unsigned int i = 1; i <= max_block_size; i++) {
    auto input = std::vector<unsigned char>(i, 'A');
    auto ciphertext = TheNewEncryptionOracle(input);
    potential_block_size++;

    if (prev_ctxt_size != ciphertext.size()) {
      prev_ctxt_size = ciphertext.size();
      printf("Ciphertext size changed. Steps: %u\n", potential_block_size);
      
      if (potential_block_size == block_size) return block_size;
      block_size = potential_block_size;
      potential_block_size = 0;
    }
  }

  printf("[x] Could not find the block size (max block size %u)\n", max_block_size);
  return 0; // could not recover the block size
}

bool IsTheNewOracleUsingEcb() {
  auto input = std::vector<unsigned char>(160, 'A');
  return challenge11::IsCiphertextEcb(input);
}

void RunChallenge() {
  printf("\n----------\nEX12: Byte-at-a-time ECB decryption (Simple)\n");
  key = challenge11::RandomAESKey();
  PrintHexBuffer(key, "SESSION KEY\n");

  printf("Checking for ECB\n");
  auto block_size = GuessBlockSize();
  if (IsTheNewOracleUsingEcb()) printf("The New Oracle is using ECB\n");
  else printf("The New Oracle is not using ECB\n");

  printf("\n\n\nChecking for PADDING ATTACK\n");
  auto input = std::vector<unsigned char>(block_size, 'A');
  for (size_t i = 0; i < 10; i++) {
    PrintHexBuffer(input, "CRAFTED INPUT");
    auto ciphertext = TheNewEncryptionOracle(input);
    PrintHexBuffer(ciphertext, "CIPHERTEXT");
    input.at(input.size() - 1)++; // change the last letter for the next one
  }
}

} // namespace challenge12