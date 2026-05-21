cmake_minimum_required(VERSION 3.15)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Project definitions
add_definitions(
    -D_CRT_SECURE_NO_DEPRECATE
    -D_CRT_SECURE_NO_WARNINGS
    -DUNICODE
    -D_UNICODE
)

project(windows_internals CXX)

add_executable(tls_test source.cpp)

target_compile_features(tls_test PUBLIC cxx_std_23)
