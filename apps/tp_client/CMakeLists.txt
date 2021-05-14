# the main tp_app 

cmake_minimum_required(VERSION 2.8.10)

set(SRCS app.cpp)
add_executable(tp_client  ${SRCS})

list(APPEND EXTRA_LIBS tp)
list(APPEND EXTRA_LIBS dot2)

list(APPEND EXTRA_HDRS ${PROJECT_BINARY_DIR})
list(APPEND EXTRA_HDRS ${CMAKE_CURRENT_SOURCE_DIR}/../src)
list(APPEND EXTRA_HDRS ${CMAKE_CURRENT_SOURCE_DIR}/../src/dot2)



target_include_directories(tp_client PUBLIC ${pwd})
target_include_directories(tp_client PUBLIC ${EXTRA_HDRS})

# target_include_directories(tp_test PUBLIC ${PROJECT_BINARY_DIR})
# target_include_directories(tp_test PUBLIC ${PROJECT_SOURCE_DIR}/tp)
# target_include_directories(tp_test PUBLIC ${PROJECT_SOURCE_DIR}/tp/ieee1609)



target_link_libraries(tp_client ${EXTRA_LIBS})