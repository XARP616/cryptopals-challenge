
set(BUILD_BASE_DIR "${CMAKE_SOURCE_DIR}/build/set1")

add_executable(set1
    ${SET1_SRC_DIR}/challenge1.cc
    ${SET1_SRC_DIR}/challenge2.cc
    ${SET1_SRC_DIR}/challenge3.cc
    ${SET1_SRC_DIR}/challenge4.cc
    ${SET1_SRC_DIR}/challenge5.cc
    ${SET1_SRC_DIR}/challenge6.cc
    ${SET1_SRC_DIR}/challenge7.cc
    ${SET1_SRC_DIR}/main.cc
)
target_link_libraries(set1 PRIVATE 
    common 
    set1_includes
    OpenSSL::SSL
    OpenSSL::Crypto
)

configure_file(${SET1_DATA_DIR}/4.txt ${BUILD_BASE_DIR}/4.txt COPYONLY)
configure_file(${SET1_DATA_DIR}/6.txt ${BUILD_BASE_DIR}/6.txt COPYONLY)
configure_file(${SET1_DATA_DIR}/6.txt ${BUILD_BASE_DIR}/7.txt COPYONLY)