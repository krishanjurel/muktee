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
time_t start_time(struct tm *tm);
// void* buf_alloc(size_t s);
// /* only alloc if addr_ != addr or s >= allocated_ */
// void *buf_realloc(void *addr, size_t s);
// void buf_free(void *addr);

#ifdef __cplusplus
}
#endif
void print_data(const char* file, const uint8_t *buf, size_t len);
#endif //__TP_UTIL_HPP__