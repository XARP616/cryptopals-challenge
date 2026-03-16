set(SET2_BUILD_DIR "${CMAKE_SOURCE_DIR}/build/set2")

add_executable(set2
  ${SET1_SRC_DIR}/challenge1.cc
  ${SET1_SRC_DIR}/challenge7.cc
  ${SET2_SRC_DIR}/challenge9.cc
  ${SET2_SRC_DIR}/challenge10.cc
  ${SET2_SRC_DIR}/challenge11.cc
  ${SET2_SRC_DIR}/challenge12.cc
  ${SET2_SRC_DIR}/challenge13.cc
  ${SET2_SRC_DIR}/challenge14.cc
  ${SET2_SRC_DIR}/challenge15.cc
  ${SET2_SRC_DIR}/main.cc
)

target_link_libraries(set2 PRIVATE
  common
  set1_includes
  set2_includes
  OpenSSL::Crypto
)

configure_file(${SET2_DATA_DIR}/10.txt ${SET2_BUILD_DIR}/10.txt COPYONLY)
