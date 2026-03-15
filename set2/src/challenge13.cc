#include <bits/stdc++.h>
#include <ranges>
#include <format>
#include <vector>
#include "challenge1.h"
#include "challenge7.h"
#include "challenge11.h"
#include "challenge13.h"

namespace challenge13 {

std::vector<unsigned char> session_key;

class Field {
 public:
  Field(std::string line) {
    // split
    auto delimiter_pos = line.find('=');
    key = line.substr(0, delimiter_pos);
    value = line.substr(delimiter_pos + 1);
  }
  
  Field(const std::string& key, const std::string& value) 
    : key(key), value(value) {}

  std::string GetKey() const { return key; }
  std::string GetValue() const { return value; }

  std::string Encode() const {
    return std::format("{}={}", key, value);
  }

 private:
  std::string key;
  std::string value;
};

class User {
 public:
  User(const std::string& email) 
    : uid("uid", "10"),
    email("email", email),
    role("role", "user") {}

  Field GetUid() { return uid; }
  Field GetEmail() { return email; }
  Field GetRole() { return role; }

  std::string Encode() {
    return std::format("{}&{}&{}", email.Encode(), uid.Encode(), role.Encode());
  }

 private:
  Field uid;
  Field email;
  Field role;
};

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

void RunChallenge() {
  printf("\n----------\nEX13: ECB cut-and-paste\n");
  session_key = challenge11::RandomAESKey();

  User user = ProfileFor("labascal@unizar.es");

  auto ciphered = CipherProfile(user);
  DecipherProfile(ciphered);

  // NO hay una comprobación de integridad de los bloques
  // por tanto, igual se podría probar a introducir un bloque con los datos
  // me interesan dentro del ciphertext.

  // B1 (16B)
  // [email=mymail@ser] [vice.com&uid=10&] [role=user#padding]
  //  =>
  // [email=mymail@ser] [vice.com&uid=10&] [role=admin]

  // CÓMO GENERAMOS UN BLOQUE QUE DIGA role=admin?

  // ParseFields("foo=bar&baz=qux&zap=zazzle"); // test parsing
}

} // challenge13