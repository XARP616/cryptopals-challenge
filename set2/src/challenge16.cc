#include <vector>
#include <string>
#include <sstream>
#include "utils.h"
#include "challenge10.h"
#include "challenge11.h"
#include "challenge13.h"
#include "challenge16.h"

namespace challenge16 {

using challenge13::Field;

std::vector<unsigned char> session_key = challenge11::RandomAESKey();
auto iv = std::vector<unsigned char>(16, '\x00');

std::vector<Field> ParseFields(const std::string& input) {
  std::stringstream stream(input);
  char delimiter = ';';
  std::string str;

  std::vector<std::string> splitted;
  while (getline(stream, str, delimiter)) {
    splitted.push_back(str);
  }

  std::vector<Field> entries;
  for (auto pair : splitted) {
    entries.push_back(Field(pair));
  }

  for (auto entry : entries) {
    printf("%s | %s\n", entry.GetKey().c_str(), entry.GetValue().c_str());
  }

  return entries;
}

std::vector<unsigned char> CipherInput(const std::string& input) {
  std::string sanitized_input = input;
  std::erase(sanitized_input, '&');
  std::erase(sanitized_input, '=');

  std::vector<unsigned char> plaintext = {sanitized_input.begin(), sanitized_input.end()};
  std::string prepend = "comment1=cooking%20MCs;userdata=";
  std::string append = ";comment2=%20like%20a%20pound%20of%20bacon";

  plaintext.insert(plaintext.begin(), prepend.begin(), prepend.end());
  plaintext.insert(plaintext.end(), append.begin(), append.end());

  return challenge10::CBCEncrypt(plaintext, iv, session_key);
}

void DecipherAndParse(std::vector<unsigned char> ciphertext) {
  auto plaintext = challenge10::CBCDecrypt(ciphertext, iv, session_key);
  PrintHexBuffer(plaintext);
  ParseFields({plaintext.begin(), plaintext.end()});
}

void RunChallenge() {
  auto c = CipherInput("admin=true");
  DecipherAndParse(c);
}

} // namespace challenge16