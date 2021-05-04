cmake_minimum_required(VERSION 2.8.10)
add_library(tp tp_util.cpp tp.cpp)
add_subdirectory(ieee1609)
target_link_libraries(ieee1609)