cmake_minimum_required(VERSION 3.15)
project(PhoenixSourceProbe CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN)

add_library(PhoenixSourceProbe SHARED
    PhoenixSourceProbe.h
    PhoenixSourceProbe.cpp
)

target_link_libraries(PhoenixSourceProbe PRIVATE
    setupapi
    advapi32
    psapi
)

set_target_properties(PhoenixSourceProbe PROPERTIES
    OUTPUT_NAME "PhoenixSourceProbe"
    SUFFIX ".dll"
)
