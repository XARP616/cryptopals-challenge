#include <bits/stdc++.h>
#include <vector>
#include <sstream>
#include "utils.h"
#include "challenge1.h"
#include "challenge7.h"
#include "challenge11.h"
#include "challenge13.h"

namespace challenge13 {

std::vector<unsigned char> session_key;
const unsigned int kBlockSize = 16;

std::vector<Field> ParseFields(std::string input) {
  std::stringstream stream(input);
  char delimiter = '&';
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

User ProfileFor(std::string email) {
  std::erase(email, '&');
  std::erase(email, '=');
  return User(email);
}

std::vector<unsigned char> CipherProfile(User user) {
  auto encoded_user = user.Encode();
  return challenge7::EncryptAesEcb({encoded_user.begin(), encoded_user.end()}, session_key);
}

void DecipherProfile(std::vector<unsigned char> user) {
  auto plaintext = challenge7::DecryptAesEcb(user, session_key);
  std::string encoded_user = {plaintext.begin(), plaintext.end()};
  ParseFields(encoded_user);
}

void PrintAsBlocks(std::string input, unsigned int block_size) {
  for (unsigned int i = 0; i < input.size(); i++) {
    if (i % block_size == 0) {
      if (i == 0) printf("[");
      else printf("] [");
    }
    
    unsigned char c = input[i];
    if (c < 0x20 || c > 0x7E) c = '.';
    printf("%c", c);

  } printf("]\n");
}

void PrintUserInfo(User u) {
  auto str = u.Encode();
  PrintAsBlocks(str, kBlockSize);
  PrintHexBuffer({str.begin(), str.end()});
}

void RunChallenge() {
  printf("\n----------\nEX13: ECB cut-and-paste\n");
  session_key = challenge11::RandomAESKey();

  //User user = ProfileFor("labascal@unizar.es");

  // NO hay una comprobación de integridad de los bloques
  // por tanto, igual se podría probar a introducir un bloque con los datos
  // me interesan dentro del ciphertext.

  // B1 (16B)
  // [email=mymail@ser] [vice.com&uid=10&] [role=user#padding]
  //  =>
  // [email=mymail@ser] [vice.com&uid=10&] [role=admin]

  // GENERATE A BLOCK THAT CONTAINS role=admin?
  // [email=me@service] [.com&uid=10&role] [=admin #padding]
  // [email=mymail@ser] [admin&uid=10&rol] [e=user]
  //                     ^ interesting block with clutter

  // [email=lav@gmail.] [com&uid=10&role=] [user#padding]
  //                                         ^ replacable

  // [email=lav@gmail.] [com&uid=10&role=] [admin&uid=10&rol]
  //                                         ^ replaced (padding?)
  
  // THE PADDING (PKCS7)
  // [admin&uid=10&rol]
  // admin (5) + padding (11) -> 0x0B

  std::string magic_user = "mymail@seradmin";
  auto padding = std::vector<unsigned char>(11, 11);
  magic_user.insert(magic_user.end(), padding.begin(), padding.end());
  
  User user = ProfileFor(magic_user);
  PrintUserInfo(user);
  
  // GET THE SECOND BLOCK
  auto ciphered = CipherProfile(user);
  auto admin_block = ciphered.data() + kBlockSize;

  User admin = ProfileFor("lav@gmail.com");
  PrintUserInfo(admin);

  auto c_admin = CipherProfile(admin);
  PrintHexBuffer(c_admin, "ADMIN ENC");

  auto replace_at = c_admin.data() + kBlockSize * 2; // third block
  memcpy(replace_at, admin_block, kBlockSize);
  PrintHexBuffer(c_admin, "ADMIN REPLACED");

  printf("DECODED PROFILE:\n");
  DecipherProfile(c_admin);

  // ParseFields("foo=bar&baz=qux&zap=zazzle"); // test parsing
}

} // challenge13