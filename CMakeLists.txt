cmake_minimum_required(VERSION 3.22)
project(krypto)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

message(STATUS "Cmake prefix path: ${CMAKE_PREFIX_PATH}")
include_directories("include")
file(GLOB_RECURSE SOURCES ${PROJECT_SOURCE_DIR}/src/*.cpp ${PROJECT_SOURCE_DIR}/src/*.c)
add_executable(${PROJECT_NAME} ${SOURCES})

# find_package(GMP REQUIRED)

target_link_libraries(${PROJECT_NAME} gmp)