#include <bits/stdc++.h>
#include <ranges>
#include "challenge13.h"

namespace challenge13 {

class Field {
 public:
  Field(std::string line) {
    // split
    char delimiter = '=';
    this->key = line.substr(0, line.find(delimiter));
    this->value = line.substr(line.find(delimiter) + 1, line.size() - 1);
  }

  std::string GetKey() { return this->key; }
  std::string GetValue() { return this->value; }


 private:
  std::string key;
  std::string value;
};

void KeyValueSplit(std::string input) {
  std::stringstream stream(input);
  char delimiter = '&';
  std::string str;

  std::vector<std::string> splitted;
  while (getline(stream, str, delimiter)) {
    splitted.push_back(str);
  }

  printf("Splitted size: %lu\n", splitted.size());
  std::vector<Field> entries;
  for (auto pair : splitted) {
    entries.push_back(Field(pair));
  }

  for (auto entry : entries) {
    printf("%s | %s\n", entry.GetKey().c_str(), entry.GetValue().c_str());
  }
}

void RunChallenge() {
  printf("\n----------\nEX13: ECB cut-and-paste\n");
  KeyValueSplit("foo=bar&baz=qux&zap=zazzle");
}

} // challenge13