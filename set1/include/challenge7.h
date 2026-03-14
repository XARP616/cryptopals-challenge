#include <vector>
#pragma once

namespace challenge7 {

void RunChallenge();

std::vector<unsigned char> EncryptAesEcb(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char> key, bool padding_enabled = true);
std::vector<unsigned char> DecryptAesEcb(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char> key);
bool EncryptAesEcbBlock(const unsigned char* plaintext, unsigned char* ciphertext, const unsigned char* key, size_t size);
bool DecryptAesEcbBlock(const unsigned char* ciphertext, unsigned char* plaintext, const unsigned char* key, size_t size);

} // namespace challenge7