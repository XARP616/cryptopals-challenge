add_executable(
  set1_tests
  set1_tests.cc
  ${SET1_SRC_DIR}/challenge1.cc
  ${SET1_SRC_DIR}/challenge2.cc
  ${SET1_SRC_DIR}/challenge3.cc
  ${SET1_SRC_DIR}/challenge4.cc
  ${SET1_SRC_DIR}/challenge5.cc
  ${SET1_SRC_DIR}/challenge6.cc
  ${SET1_SRC_DIR}/challenge7.cc
)

target_link_libraries(
  set1_tests 
  common 
  set1_includes 
  GTest::gtest_main 
  ${OPENSSL_LIBRARIES}
)

configure_file(${SET1_DATA_DIR}/4.txt 4.txt COPYONLY)
configure_file(${SET1_DATA_DIR}/6.txt 6.txt COPYONLY)
configure_file(${SET1_DATA_DIR}/7.txt 7.txt COPYONLY)