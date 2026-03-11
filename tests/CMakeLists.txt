#add_library(common_includes INTERFACE)
#target_include_directories(common_includes INTERFACE ../set1/include)
set(SRC_DIR "../set1/src")
set(DATA_DIR "../set1/data")

add_executable(
  set1_tests
  set1_tests.cc
  ${SRC_DIR}/challenge1.cc
  ${SRC_DIR}/challenge2.cc
  ${SRC_DIR}/challenge3.cc
  ${SRC_DIR}/challenge4.cc
  ${SRC_DIR}/challenge5.cc
  ${SRC_DIR}/challenge6.cc
)

target_link_libraries(set1_tests GTest::gtest_main common_includes common)

configure_file(${DATA_DIR}/4.txt 4.txt COPYONLY)
configure_file(${DATA_DIR}/6.txt 6.txt COPYONLY)
configure_file(${DATA_DIR}/6.txt 7.txt COPYONLY)