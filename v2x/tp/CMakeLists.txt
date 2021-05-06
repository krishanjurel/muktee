cmake_minimum_required(VERSION 2.8.10)
add_library(tp tp_util.cpp tp.cpp)

target_include_directories(tp PUBLIC ${PROJECT_SOURCE_DIR})
target_include_directories(tp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(tp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ieee1609)

add_subdirectory(ieee1609)
