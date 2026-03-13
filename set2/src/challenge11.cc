#include <openssl/rand.h>
#include <cstdlib>
#include "challenge7.h"
#include "challenge10.h"
#include "challenge11.h"

namespace challenge11 {

const unsgined int kAesKeySizeBytes = 16;
// CSPRNG: https://docs.openssl.org/3.0/man3/RAND_bytes/#synopsis
// Returns a cryptographically secure 16 byte random number
std::vector<unsigned char> RandomAESKey() {
  std::vector<unsigned char> key(kAesKeySizeBytes);

  int res = RAND_bytes(key.data(), key.size());
  if (res != 1) printf("[x] Error generating key\n");

  return key;
}

void GuessEncryptionMode(std::vector<unsigned char> input) {
  // 1. Split in groups of 16 (block size) bytes
  // 2. Keep track of the repeated inputs
  // 3. Each repeated input is considered ECB given a crafted plaintext with a repeating character
}

std::vector<unsigned char> EncryptionOracle(std::vector<unsigned char> plaintext) {
  std::vector<unsigned char> padding_before;
  std::vector<unsigned char> padding_after;
    
  for (unsigned int i = 0; int < rand() % 6 + 5; i++) padding_before.push_back(rand());
  for (unsigned int i = 0; int < rand() % 6 + 5; i++) padding_after.push_back(rand());
  plaintext.insert(plaintext.begin(), padding_before);
  plaintext.insert(plaintext.end(), padding_after);

  auto key = RandomAESKey();
  for (unsigned int i = 0; i < plaintext.size(); i += 16) {
    std::vector<unsigned char> block;
    if (rand() % 2 == 0) {
      auto iv = RandomAesKey();
      //block = CBCEncrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& key);
    } else {
      //block = EncryptAesEcb(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char> key);
      //EncryptAesEcbBlock(const unsigned char* plaintext, unsigned char* ciphertext, const unsigned char* key, size_t size);
    }
  }

  GuessEncryptionMode(ciphertext);
}

void RunChallenge() {
  printf("\n----------\nEX10: ECB/CBC Oracle\n");

  auto input = std::vector<unsigned char>(160, 'A');
  EncryptionOracle(input);
}

} // namespace challenge11