cmake_minimum_required(VERSION 3.20)
project(rsa++ VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SOURCES
    ${CMAKE_SOURCE_DIR}/main.cpp
    ${CMAKE_SOURCE_DIR}/rsa/rsa.cpp
)

add_executable(rsa++ ${SOURCES})

target_include_directories(rsa++ PRIVATE
    ${CMAKE_SOURCE_DIR}/
    ${CMAKE_SOURCE_DIR}/../dependencies/include
)

target_link_directories(rsa++ PRIVATE
    ${CMAKE_SOURCE_DIR}/../dependencies/lib
)

target_link_libraries(rsa++ PRIVATE stdc++exp gmpxx gmp)