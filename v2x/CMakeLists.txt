cmake_minimum_required(VERSION 2.8.12)

set(TARGET tp_client)
PROJECT(${TARGET})
SET(CMAKE_CXX_STANDARD 11)
# set(CMAKE_C_COMPILER /bin/x86_64-linux-gnu-gcc-9)
# set(CMAKE_CXX_COMPILER /bin/x86_64-linux-gnu-g++-9)

#add_executable(${TARGET}  ieee1609dot2.cpp ieee1609dot2cert.cpp ieee1609dot2encdec.cpp ieee1609dot2data.cpp)
add_compile_options(-O3 -fpermissive -Wunused-variable)
set(CMAKE_BINARY_DIR ${pwd})
# target_include_directories(${TARGET} PUBLIC ${pwd})
# target_include_directories(${TARGET} PUBLIC /usr/include)
# target_include_directories(${TARGET} PUBLIC /usr/include/openssl)

# target_link_libraries(${TARGET} crypto ssl pthread rt config++)
add_subdirectory(tp_client ${CMAKE_BINARY_DIR})
add_subdirectory(tp ${CMAKE_BINARY_DIR})




