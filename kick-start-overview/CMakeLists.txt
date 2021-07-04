cmake_minimum_required(VERSION 2.8)
PROJECT(add)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED true)



if(MSVC)
# SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
SET(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MT")
endif()


MACRO(add_example name)
  ADD_EXECUTABLE(${name} ${name}.c)
ENDMACRO()

add_example(IO)
add_example(buffer_overflow)
add_example(char_overflow)
add_example(stack)

