cmake_minimum_required(VERSION 3.23)
project(fileDuplicateDetection)

set(CMAKE_CXX_STANDARD 20)

# OpenSSL
set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD/libcrypto.lib")
set(OPENSSL_SSL_LIBRARY "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD/libssl.lib")

find_package(OpenSSL REQUIRED)

add_executable(fileDuplicateDetection main.cpp)

# Link OpenSSL libraries to your executable
target_link_libraries(fileDuplicateDetection OpenSSL::Crypto OpenSSL::SSL)
