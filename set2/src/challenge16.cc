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
const unsigned int kBlockSize = 16;
auto iv = std::vector<unsigned char>(kBlockSize, '\x00');


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
  std::erase(sanitized_input, ';');
  std::erase(sanitized_input, '=');

  std::vector<unsigned char> plaintext = {sanitized_input.begin(), sanitized_input.end()};
  std::string prepend = "comment1=cooking%20MCs;userdata=";
  std::string append = ";comment2=%20like%20a%20pound%20of%20bacon";

  plaintext.insert(plaintext.begin(), prepend.begin(), prepend.end());
  plaintext.insert(plaintext.end(), append.begin(), append.end());

  PrintHexBuffer(plaintext, "PLAINTEXT");
  return challenge10::CBCEncrypt(plaintext, iv, session_key);
}

void DecipherAndParse(std::vector<unsigned char> ciphertext) {
  auto plaintext = challenge10::CBCDecrypt(ciphertext, iv, session_key);
  PrintHexBuffer(plaintext);
  auto fields = ParseFields({plaintext.begin(), plaintext.end()});

  for (auto field : fields) {
    if (field.GetKey() == "admin" && field.GetValue() == "true") 
      printf("User is an admin\n");
  }
}

void Testing() {
  auto p = std::vector<unsigned char>(48, 'A');
  PrintHexBuffer(p, "PLAINTEXT");
  auto c = challenge10::CBCEncrypt(p, iv, session_key);
  PrintHexBuffer(c, "CIPHERTEXT");

  auto d = challenge10::CBCDecrypt(c, iv, session_key);
  PrintHexBuffer(d, "DECIPHERED");

  size_t pos = 16;
  c[pos] ^= 0x01; //flip 

  PrintHexBuffer(c, "SCRAMBLED");

  d = challenge10::CBCDecrypt(c, iv, session_key);
  PrintHexBuffer(d, "SCRAMBLE DEC.");
}

void POC() {
  auto c = CipherInput("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  PrintHexBuffer(c, "CIPHERTEXT");
  // para modificar c31, modificamos c41
  unsigned char c31 = c[0x20];
  unsigned char d31 = c31 ^ 0x41; // p31 ('A'), valor conocido y controlado
  // d31 es el valor resultante de descifrar c41

  // 0x61 es 'a', el valor que queremos obtener
  unsigned char s41 = d31 ^ 'a'; // scramble fila 4, columna 1
  
  c[0x20] = s41;

  PrintHexBuffer(c, "SCRAMBLED");
  DecipherAndParse(c);
}

void Scramble() {
  std::string target_string = ";admin=true;pwnd=";
  std::string padding = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  // the padding has to be greater than 16
  // we are screwing the first row of padding in order to
  // craft the desired string on the next block
  
  auto ciphertext = CipherInput(padding);
  unsigned int offset = kBlockSize * 2;
  for (unsigned int i = 0; i < kBlockSize; i++) {
    unsigned char c11 = ciphertext[i + offset];
    unsigned char d11 = c11 ^ padding[i];
    unsigned char s21 = d11 ^ target_string[i];

    ciphertext[i + offset] = s21;
  }
  
  DecipherAndParse(ciphertext);
}

void RunChallenge() {
  printf("\n----------\nEX16: CBC bitflipping attacks\n");
  //POC(); // working!
  Scramble();
  //Testing();
}

} // namespace challenge16