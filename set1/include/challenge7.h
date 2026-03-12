#include <vector>
#pragma once

namespace challenge7 {

void RunChallenge();

std::vector<unsigned char> EncryptAesEcb(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char> key);
std::vector<unsigned char> DecryptAesEcb(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char> key);

} // namespace challenge7