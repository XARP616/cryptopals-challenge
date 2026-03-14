#include "utils.h"
#include "challenge1.h"
#include "challenge7.h"
#include "challenge9.h"
#include "challenge10.h"

namespace challenge10 {

const unsigned int kBlockSizeBytes = 16;

// The CBC mode takes the output of a block and XORs it with the
// next block. The first block of the chain is XORed with the IV.
std::vector<unsigned char> CBCEncrypt(
  const std::vector<unsigned char>& plaintext, 
  const std::vector<unsigned char>& iv, 
  const std::vector<unsigned char>& key,
  bool padding) {
  auto cbc_ciphertext = plaintext; // copy the plaintext over to the ciphertext
  
  // 1. Pad the buffer
  if (padding) challenge9::PKCS7Padding(cbc_ciphertext, kBlockSizeBytes);

  // 2. XOR the first block with the IV
  XorBuffer(cbc_ciphertext.data(), iv.data(), kBlockSizeBytes);
  
  // 3. Encrypt the blocks
  auto last_block = cbc_ciphertext.data() + cbc_ciphertext.size() - kBlockSizeBytes;
  for (size_t i = 0; i < cbc_ciphertext.size(); i += kBlockSizeBytes) {
    auto current_block = cbc_ciphertext.data() + i;
    // 3b. Cipher the block
    challenge7::EncryptAesEcbBlock(
      current_block,
      current_block,
      key.data(),
      kBlockSizeBytes
    );

    // 3b. XOR with the next block (CBC) - except the last block
    auto next_block = current_block + kBlockSizeBytes;
    if (next_block <= last_block) XorBuffer(next_block, current_block, kBlockSizeBytes);
  }

  return cbc_ciphertext;
}

std::vector<unsigned char> CBCDecrypt(
  const std::vector<unsigned char>& ciphertext, 
  const std::vector<unsigned char>& iv, 
  const std::vector<unsigned char>& key) {
  auto cbc_plaintext = ciphertext;
  
  for (int i = cbc_plaintext.size() - kBlockSizeBytes; i >= 0; i -= kBlockSizeBytes) {
    auto current_block = cbc_plaintext.data() + i;
    challenge7::DecryptAesEcbBlock(current_block, current_block, key.data(), kBlockSizeBytes);

    auto prev_block = current_block - kBlockSizeBytes;
    if (i >= kBlockSizeBytes) XorBuffer(current_block, prev_block, kBlockSizeBytes);
  }

  XorBuffer(cbc_plaintext.data(), iv.data(), kBlockSizeBytes);

  // TODO: remove the padding

  return cbc_plaintext;
}

void RunChallenge() {
  printf("\n----------\nEX10: CBC Encryption and Decryption\n");
  
  std::string key = "YELLOW SUBMARINE";
  std::vector<unsigned char> iv(16, '\0');
  std::string plaintext_str;
  if (!ParseFile("10.txt", plaintext_str)) return;
  
  std::vector<unsigned char> ciphertext = challenge1::Base64Decode(plaintext_str);
  auto plaintext = CBCDecrypt(ciphertext, iv, {key.begin(), key.end()});
  printf("Decrypted file:");
  PrintHexBuffer(plaintext);
}

}