cmake_minimum_required(VERSION 3.20)
project(BedrockScanner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(BedrockScanner
    src/main.cpp
    src/process.cpp
    src/pattern.cpp
)

target_include_directories(BedrockScanner PRIVATE src)
target_compile_definitions(BedrockScanner PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)

if(MSVC)
    target_compile_options(BedrockScanner PRIVATE /W4 /permissive- /EHsc)
endif()
