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

// Returns true if encrypted with ECB, false if encrypted with CBC
bool IsCiphertextEcb(const std::vector<unsigned char>& input) {
  std::set<std::vector<unsigned char>> blocks;
  for (auto block_start = input.begin(); block_start < input.end(); block_start += kBlockSizeBytes) {
    auto block_end = block_start + kBlockSizeBytes;
    std::vector<unsigned char> current_block(block_start, block_end);

    if (blocks.contains(current_block)) return true;
    else blocks.insert(current_block);
  }

  return false;
}

// Inserts 5 to 10 random bytes at the beginning and end of the buffer
void AddRandomBytes(std::vector<unsigned char>& plaintext) {
  std::vector<unsigned char> padding_before;
  std::vector<unsigned char> padding_after;
    
  for (unsigned int i = 0; i < rand() % 6 + 5; i++) padding_before.push_back(rand());
  for (unsigned int i = 0; i < rand() % 6 + 5; i++) padding_after.push_back(rand());
  plaintext.insert(plaintext.begin(), padding_before.begin(), padding_before.end());
  plaintext.insert(plaintext.end(), padding_after.begin(), padding_after.end());
}

std::vector<unsigned char> EncryptionOracle(std::vector<unsigned char> plaintext) {
  AddRandomBytes(plaintext);
  auto key = RandomAESKey();

  std::vector<unsigned char> ciphertext;
  if (rand() % 2 == 0) {
    printf("Oracle says:   CBC!\n");
    auto iv = RandomAESKey();
    ciphertext = challenge10::CBCEncrypt(plaintext, iv, key);
  } else {
    printf("Oracle says:   ECB!\n");
    ciphertext = challenge7::EncryptAesEcb(plaintext, key);
  }

  return ciphertext;
}

void RunChallenge() {
  printf("\n----------\nEX11: ECB/CBC Oracle\n");

  for (int i = 0; i < 10; i++) {
    auto input = std::vector<unsigned char>(160, 'A');
    auto ciphertext = EncryptionOracle(input);
    printf("Detector says: ");
    if (IsCiphertextEcb(ciphertext)) {
      printf("ECB!\n");
    } else printf("CBC!\n");
    printf("---\n");
  }
  
}

} // namespace challenge11