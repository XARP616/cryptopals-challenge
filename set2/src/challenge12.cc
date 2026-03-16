#include <vector>
#include "utils.h"
#include "challenge1.h"
#include "challenge7.h"
#include "challenge11.h"
#include "challenge12.h"

namespace challenge12 {

std::vector<unsigned char> session_key;

void InitKey() {
  session_key = challenge11::RandomAESKey();
  //PrintHexBuffer(session_key, "SESSION KEY\n");
}

std::vector<unsigned char> TheNewEncryptionOracle(std::vector<unsigned char> plaintext) {
  std::string append = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
  auto decoded = challenge1::Base64Decode(append);
  plaintext.insert(plaintext.end(), decoded.begin(), decoded.end());

  if (session_key.size() == 0) InitKey();
  return challenge7::EncryptAesEcb(plaintext, session_key);
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

// Gets the ciphertext block where the input is padding and the last byte will be next unkown byte of the secret
std::vector<unsigned char> GetTargetCiphertextBlock(const std::vector<unsigned char>& test_input, unsigned int max_output_len) {
  auto target_output = TheNewEncryptionOracle(test_input);
  if (target_output.size() > max_output_len) target_output.resize(max_output_len);
  return target_output;
}

void BreakECB(unsigned int block_size) {
  printf("\n============= BREAKING ECB ================\n");
  std::vector<unsigned char> reconstructed_plaintext;

  unsigned int block_count = 1;
  bool remaining_characters = true;
  while (remaining_characters) {
    unsigned int dummy_bytes = block_size * block_count - reconstructed_plaintext.size() - 1;
    
    auto crafted_input = std::vector<unsigned char>(dummy_bytes, 'A');
    auto target_output = GetTargetCiphertextBlock(crafted_input, block_size * block_count);

    crafted_input.insert(crafted_input.end(), reconstructed_plaintext.begin(), reconstructed_plaintext.end());
    crafted_input.push_back('?'); // guess token (this character will be replaced)

    // Brute force
    unsigned int character;
    for (character = 0x00; character <= 0xFF; character++) {
      unsigned char c = static_cast<unsigned char>(character);
      //printf("[%c = 0x%02X]\n", c, c);
      crafted_input.at(crafted_input.size() - 1) = c; // replace the last character
      auto ciphertext = TheNewEncryptionOracle(crafted_input);

      // discard all but the first bytes
      if (ciphertext.size() > block_count * block_size) ciphertext.resize(block_count * block_size);

      // if we find a ciphertext that matches our input
      if (ciphertext == target_output) {
        reconstructed_plaintext.push_back(c);
        break;
      }
    }

    if (character > 0xFF) {
      remaining_characters = false;
      printf("[!] Failed to find an ASCII character. Message end\n");
    }

    if (dummy_bytes == 0) block_count++;
    //PrintHexBuffer(reconstructed_plaintext, "PLAINTEXT SO FAR:");
  }

  PrintHexBuffer(reconstructed_plaintext, "FINAL PLAINTEXT");
}

void RunChallenge() {
  printf("\n----------\nEX12: Byte-at-a-time ECB decryption (Simple)\n");

  printf("Checking for ECB\n");
  auto block_size = GuessBlockSize();
  if (IsTheNewOracleUsingEcb()) printf("The New Oracle is using ECB\n");
  else printf("The New Oracle is not using ECB\n");

  BreakECB(block_size);
}

} // namespace challenge12