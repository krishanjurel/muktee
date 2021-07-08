cmake_minimum_required(VERSION 2.8.10)

set(SRCS tp_util.cpp tp.cpp tp.hpp tp_util.hpp)
add_library(tp STATIC ${SRCS})


target_include_directories(tp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(tp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/dot2)

add_definitions(-DUSE_LIB_CONFIG)
if(USE_COSMO_TP)
    target_include_directories(tp PUBLIC ${CMAKE_SOURCE_DIR}/third_party/libconfig/lib)
    # libconfig is provided by the runtime
    target_link_libraries(tp PUBLIC config_cpp)
else()
    target_link_libraries(tp PUBLIC config++)
endif()

add_subdirectory(dot2)