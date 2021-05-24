cmake_minimum_required(VERSION 2.8.10)
add_library(tp tp_util.cpp tp.cpp tp.hpp tp_util.hpp)

message(${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(tp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(tp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/dot2)

if(USE_COSMO_TP)
    add_definitions(-DUSE_LIB_CONFIG)
    target_include_directories(tp PUBLIC ${CMAKE_SOURCE_DIR}/third_part/libconfig/lib)
    # libconfig is provided by the runtime
    target_link_libraries(tp PUBLIC config_cpp)
endif()

add_subdirectory(dot2)
