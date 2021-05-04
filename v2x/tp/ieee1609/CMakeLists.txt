cmake_minimum_required(VERSION 2.8.10)

set(SRCS dot2cert.cpp dot2data.cpp dot2encdec.cpp)
set(TARGET2 ieee1609)

add_library(${TARGET2} ${SRCS})

target_include_directories(${TARGET2} PUBLIC ${pwd})
target_include_directories(${TARGET2} PUBLIC /usr/include)
target_include_directories(${TARGET2} PUBLIC /usr/include/openssl)
target_include_directories(${TARGET2} PUBLIC ${pwd}/..)

target_link_libraries(${TARGET2} crypto ssl pthread rt config++)