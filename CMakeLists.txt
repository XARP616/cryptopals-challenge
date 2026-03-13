cmake_minimum_required(VERSION 3.28.3)

project(CryptoPalsProject CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Dependencies
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
FetchContent_MakeAvailable(googletest)

# https://cmake.org/cmake/help/latest/module/FindOpenSSL.html
find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")

add_library(common INTERFACE)
target_include_directories(common INTERFACE ${PROJECT_SOURCE_DIR}/common/include)

# SET 1
add_library(set1_includes INTERFACE)
target_include_directories(set1_includes INTERFACE ${PROJECT_SOURCE_DIR}/set1/include)
set(SET1_BASE_DIR "${CMAKE_SOURCE_DIR}/set1")
set(SET1_SRC_DIR "${SET1_BASE_DIR}/src")
set(SET1_DATA_DIR "${SET1_BASE_DIR}/data")
add_subdirectory(set1)

# SET 2
add_library(set2_includes INTERFACE)
target_include_directories(set2_includes INTERFACE ${PROJECT_SOURCE_DIR}/set2/include)
set(SET2_BASE_DIR "${CMAKE_SOURCE_DIR}/set2")
set(SET2_SRC_DIR "${SET2_BASE_DIR}/src")
set(SET2_DATA_DIR "${SET2_BASE_DIR}/data")
add_subdirectory(set2)

# SET 3
#add_subdirectory(set3)

# TESTS
enable_testing()
add_subdirectory(tests)