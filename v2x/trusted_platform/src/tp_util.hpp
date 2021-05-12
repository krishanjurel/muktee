#ifndef __TP_UTIL_HPP__
#define __TP_UTIL_HPP__

#include <stdio.h>
#include <string.h>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <iomanip>

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif
// void print_data(const char* file, const uint8_t *buf, size_t len);
time_t start_time(struct tm *tm);

#ifdef __cplusplus
}
#endif

#endif //__TP_UTIL_HPP__