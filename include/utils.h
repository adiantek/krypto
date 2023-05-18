#pragma once

#include <gmp.h>
#include <stdint.h>

void print_num(char *name, mpz_t num);
void print_hex(char *prefix, uint8_t *data, size_t len);
void print_msg(uint8_t *data, size_t len);
void print_matrix(uint32_t *matrix, size_t size);
uint32_t pack4(uint8_t *num);
void unpack4(uint32_t src, uint8_t *dst);
uint32_t rotl32(uint32_t x, int n);
