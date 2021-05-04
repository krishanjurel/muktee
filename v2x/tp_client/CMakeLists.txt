# the main tp_app 

cmake_minimum_required(VERSION 2.8.10)

set(SRCS app.cpp)
set (TARGET1 v2x)

add_executable(${TARGET1}  ${SRCS})

target_include_directories(${TARGET1} PUBLIC ${pwd})
target_include_directories(${TARGET1} PUBLIC {PROJECT_SOURCE_DIR}/tp)
target_include_directories(${TARGET1} PUBLIC {PROJECT_SOURCE_DIR}/tp/ieee1609)


target_link_libraries(${TARGET1} tp ieee1609)