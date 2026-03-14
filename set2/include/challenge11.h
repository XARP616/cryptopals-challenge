#include <vector>
#pragma once

namespace challenge11 {

void RunChallenge();

std::vector<unsigned char> RandomAESKey();
bool IsCiphertextEcb(const std::vector<unsigned char>& input);

}