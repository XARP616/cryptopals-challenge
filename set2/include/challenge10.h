#include <vector>
#pragma once

namespace challenge10 {

void RunChallenge();

std::vector<unsigned char> CBCEncrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& key);
std::vector<unsigned char> CBCDecrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& key);

}