#include <string>
#include <format>
#pragma once

namespace challenge13 {

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

std::vector<Field> ParseFields(std::string input);

void RunChallenge();

} // namespace challenge13