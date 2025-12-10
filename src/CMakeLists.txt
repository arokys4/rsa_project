cmake_minimum_required(VERSION 3.10)
project(RSA_Project)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(LIB_DIR "${CMAKE_SOURCE_DIR}/../dependencies/lib")
set(INCLUDE_DIR "${CMAKE_SOURCE_DIR}/../dependencies/include")

include_directories(${INCLUDE_DIR})

find_library(GMP_LIB NAMES libgmp.a gmp PATHS ${LIB_DIR} NO_DEFAULT_PATH)
find_library(GMPXX_LIB NAMES libgmpxx.a gmpxx PATHS ${LIB_DIR} NO_DEFAULT_PATH)

add_executable(rsa_app main.cpp rsa/rsa.cpp)

target_link_libraries(rsa_app PRIVATE ${GMPXX_LIB} ${GMP_LIB})