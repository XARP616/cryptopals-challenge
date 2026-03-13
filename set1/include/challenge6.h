#pragma once

namespace challenge6 {

void RunChallenge();

unsigned int CalculateHammingDistanceBits(unsigned char* buffer1, unsigned char* buffer2, size_t input_size);
std::vector<unsigned char> BreakRepeartingXOR(std::vector<unsigned char>& ciphertext);

} // namespace challenge6