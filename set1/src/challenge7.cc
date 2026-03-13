#include <stdio.h>
#include <fstream>

#include <openssl/evp.h>
#include "utils.h"
#include "challenge1.h"
#include "challenge7.h"

namespace challenge7 {

bool EncryptAesEcbBlock(const unsigned char* plaintext, unsigned char* ciphertext, const unsigned char* key, size_t size) {
  int processed_bytes;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    printf("[x] Failed to create EVP_CIPHER_CTX\n");
    return false;
  }

  if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr) != 1) {
    printf("Failed to initialize encryption\n");
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  EVP_CIPHER_CTX_set_padding(ctx, 0);

  if (EVP_EncryptUpdate(ctx, ciphertext, &processed_bytes, plaintext, size) != 1) {
    printf("[x] Failed to encrypt data\n");
    EVP_CIPHER_CTX_free(ctx);
    return false;
  }

  EVP_CIPHER_CTX_free(ctx);
  return true;
}

// https://docs.openssl.org/3.0/man3/EVP_aes_128_gcm/#name
// https://docs.openssl.org/3.0/man3/EVP_EncryptInit/#description
// https://stackoverflow.com/questions/5665698/evp-decryptfinal-ex-error-on-openssl
// https://github.com/mohabouz/CPP-AES-OpenSSL-Encrypt/blob/master/utils.cpp
// https://friendlyuser.github.io/posts/tech/cpp/Using_OpenSSL_in_C++_A_Comprehensive_Guide/
std::vector<unsigned char> EncryptAesEcb(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char> key) {
  std::vector<unsigned char> ciphertext(plaintext.size() + 16); // maximum possible padding (ECB: input length has to be multiple of 16)
  int plaintext_len = plaintext.size();
  int new_ciphertext_len, processed_bytes;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    printf("[x] Failed to create EVP_CIPHER_CTX\n");
    return {};
  }

  if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr) != 1) {
    printf("Failed to initialize encryption\n");
    EVP_CIPHER_CTX_free(ctx);
    return {};
  }

  //EVP_CIPHER_CTX_set_padding(ctx, 0);

  if (EVP_EncryptUpdate(ctx, ciphertext.data(), &processed_bytes, plaintext.data(), plaintext_len) != 1) {
    printf("[x] Failed to encrypt data\n");
    EVP_CIPHER_CTX_free(ctx);
    return {};
  }
  new_ciphertext_len = processed_bytes;

  auto last_error = EVP_EncryptFinal_ex(ctx, ciphertext.data() + processed_bytes, &processed_bytes);
  if (last_error != 1) {
    printf("[x] Failed to encrypt the final bytes: %i\n", last_error);
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
  }
  new_ciphertext_len += processed_bytes;

  ciphertext.resize(new_ciphertext_len);

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext;
}

std::vector<unsigned char> DecryptAesEcb(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char> key) {
  std::vector<unsigned char> plaintext(ciphertext.size());
  int ciphertext_len = ciphertext.size();
  int new_plaintext_len, processed_bytes;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) {
    printf("[x] Failed to create EVP_CIPHER_CTX\n");
    return {};
  }

  if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key.data(), nullptr) != 1) {
    printf("[x] Failed to initialize decryption\n");
    EVP_CIPHER_CTX_free(ctx);
    return {};
  }

  //EVP_CIPHER_CTX_set_padding(ctx, 0);

  if (EVP_DecryptUpdate(ctx, plaintext.data(), &processed_bytes, ciphertext.data(), ciphertext_len) != 1) {
    printf("[x] Failed to decrypt data\n");
    EVP_CIPHER_CTX_free(ctx);
    return {};
  }
  new_plaintext_len = processed_bytes;

  if (EVP_DecryptFinal_ex(ctx, plaintext.data() + processed_bytes, &processed_bytes) != 1) {
    printf("[x] Failed to decrypt the final bytes\n");
    EVP_CIPHER_CTX_free(ctx);
    return {};
  }
  new_plaintext_len += processed_bytes;

  plaintext.resize(new_plaintext_len);

  EVP_CIPHER_CTX_free(ctx);
  return plaintext;
}

void RunChallenge() {
  std::string input;
  std::string key = "YELLOW SUBMARINE";

  printf("\n----------\nEX7: AES ECB\n");
  
  if (!ParseFile("7.txt", input)) {
    printf("[x] Failed to open 7.txt\n");
    return;
  }

  auto decoded = challenge1::Base64Decode(input);
  auto plaintext = DecryptAesEcb(decoded, {key.begin(), key.end()});

  printf("> Plaintext buffer: \n");
  PrintCharVectorAsString(plaintext);

  auto ciphertext = EncryptAesEcb(plaintext, {key.begin(), key.end()});
  if (ciphertext == decoded) printf("> Encrypted and original buffers match\n");
  else printf("! Ciphertext and original do not match\n");
}

} // namespace challenge7