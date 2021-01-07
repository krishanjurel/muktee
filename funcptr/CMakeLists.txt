cmake_minimum_required(VERSION 2.8.12)

SET(projname funcptr)

PROJECT(${projname})
SET(CMAKE_CXX_STANDARD 11)


if(MSVC)
SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
endif()

# include_directories( {DIRS})

MACRO(add_example name)
  ADD_EXECUTABLE(${name} ${name}.cpp)
  #TARGET_LINK_LIBRARIES(${name} {LIBS} )
ENDMACRO()

add_example(${projname})
