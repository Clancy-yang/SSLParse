cmake_minimum_required(VERSION 3.18)
project(SSLParse)

set(CMAKE_CXX_STANDARD 11)

set(INC_DIR /usr/local/openssl/lib)
set(LINK_DIR /usr/local/lib)

include_directories(${INC_DIR} include)
link_directories(${LINK_DIR})

SET(DPDK_LIBS "-lcrypto")

add_executable(SSLParse main.cpp
        include/base64.h
        include/base64.cpp
        include/SSLParse.h
        include/SSLParse.cpp)

target_link_libraries(SSLParse
        crypto
        ssl
)