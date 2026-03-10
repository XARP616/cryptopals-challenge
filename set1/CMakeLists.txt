cmake_minimum_required(VERSION 3.28.3)

project(CryptoPalsBlock1)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCE_BASE_DIR "${CMAKE_SOURCE_DIR}/src")
set(BUILD_BASE_DIR "${CMAKE_SOURCE_DIR}/build")
set(DATA_BASE_DIR)

add_library(common_includes INTERFACE)
target_include_directories(common_includes INTERFACE ${PROJECT_SOURCE_DIR}/include)

add_executable(set1
        ${SOURCE_BASE_DIR}/challenge1.cc
        ${SOURCE_BASE_DIR}/challenge2.cc
        ${SOURCE_BASE_DIR}/challenge3.cc
        ${SOURCE_BASE_DIR}/challenge4.cc
        ${SOURCE_BASE_DIR}/challenge5.cc
        ${SOURCE_BASE_DIR}/challenge6.cc
        ${SOURCE_BASE_DIR}/main.cc
)
target_link_libraries(set1 PRIVATE common_includes)

configure_file(data/4.txt ${BUILD_BASE_DIR}/4.txt COPYONLY)
configure_file(data/6.txt ${BUILD_BASE_DIR}/6.txt COPYONLY)