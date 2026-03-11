cmake_minimum_required(VERSION 3.28.3)

project(CryptoPalsProject CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
FetchContent_MakeAvailable(googletest)

add_library(common INTERFACE)
target_include_directories(common INTERFACE ${PROJECT_SOURCE_DIR}/common/include)

enable_testing()
add_subdirectory(tests)

add_subdirectory(set1)
#add_subdirectory(set2)
#add_subdirectory(set3)