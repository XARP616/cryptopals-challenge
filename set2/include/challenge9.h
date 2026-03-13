#include <vector>
#pragma once

namespace challenge9 {

void RunChallenge();

void PKCS7Padding(std::vector<unsigned char>& input, size_t block_length);

} // namespace challenge9