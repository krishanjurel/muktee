cmake_minimum_required(VERSION 2.8.10)
add_library(tp tp_util.cpp tp.cpp tp.hpp tp_util.hpp)

message(${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(tp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(tp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/dot2)

add_subdirectory(dot2)
