cmake_minimum_required(VERSION 3.20)
project(MineMod LANGUAGES CXX)

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

add_library(MineMod SHARED
    client/mine_mod.cpp
)
target_compile_definitions(MineMod PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
set_target_properties(MineMod PROPERTIES OUTPUT_NAME "MineMod")

add_executable(MineModLoader
    loader/main.cpp
)
target_compile_definitions(MineModLoader PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
set_target_properties(MineModLoader PROPERTIES OUTPUT_NAME "MineModLoader")

if(MSVC)
    target_compile_options(BedrockScanner PRIVATE /W4 /permissive- /EHsc)
    target_compile_options(MineMod PRIVATE /W4 /permissive- /EHsc)
    target_compile_options(MineModLoader PRIVATE /W4 /permissive- /EHsc)
endif()
