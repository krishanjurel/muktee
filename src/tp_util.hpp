#ifndef __TP_UTIL_HPP__
#define __TP_UTIL_HPP__

#include <stdio.h>
#include <string.h>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>

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
int file_read(const char *file, uint8_t **buf, size_t *len);
int file_write(const char *file, const uint8_t *buf, size_t len);
/* returns a vector of strings seperated in the path, strictly for unix systems */
int file_path_create(std::string path);
#endif //__TP_UTIL_HPP__