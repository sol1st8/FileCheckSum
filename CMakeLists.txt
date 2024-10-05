cmake_minimum_required(VERSION 3.11)

project(hash CXX)
set(CMAKE_CXX_STANDARD 17)

include(${CMAKE_BINARY_DIR}/conanbuildinfo_multi.cmake)
conan_basic_setup(TARGETS)

add_executable(hash main.cpp)

target_include_directories(hash PRIVATE CONAN_PKG::cryptopp)
target_link_libraries(hash CONAN_PKG::cryptopp)
