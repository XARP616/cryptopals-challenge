#pragma once

namespace challenge14 {

void RunChallenge();

size_t InitRandomText(size_t text_len = -1);
size_t GuessRandomTextSize();
bool RegenerateRandomText(size_t size);

}