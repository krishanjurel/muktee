cmake_minimum_required(VERSION 2.8.12)

PROJECT(submission)
SET(CMAKE_CXX_STANDARD 11)


#############  Common Instructions for all Users  ############
if(MSVC)
SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
endif()

MACRO(add_example name)
  ADD_EXECUTABLE(${name} ${name}.c)
ENDMACRO()

add_example(ap_grid3x3)
