cmake_minimum_required(VERSION 2.8.12)

set(TARGET v2x)
PROJECT(${TARGET})
SET(CMAKE_CXX_STANDARD)

add_executable(${TARGET}  ieee1609dot2.cpp ieee1609dot2cert.cpp)
add_compile_options(-Wall -O3)
target_include_directories(${TARGET} PUBLIC ${pwd})
target_include_directories(${TARGET} PUBLIC /usr/include)
target_include_directories(${TARGET} PUBLIC /usr/include/openssl)

target_link_libraries(${TARGET} crypto ssl pthread rt config++)




