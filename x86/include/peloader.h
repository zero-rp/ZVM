#ifndef PELOADER_H
#define PELOADER_H

# include <stdint.h>


bool loadPE(char* code, size_t* codeSize, char* data, size_t* dataSize, char* raw, size_t size);

#endif