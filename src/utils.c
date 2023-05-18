#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utils.h>

void print_num(char *name, mpz_t num) {
    char *str = mpz_get_str(NULL, 16, num);
    printf("%s: %s%s\n", name, strlen(str) & 1 ? "0" : "", str);
    free(str);
}

void print_hex(char *prefix, uint8_t *data, size_t len) {
    printf("%s: ", prefix);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if (i + 1 != len) {
            printf(":");
        }
    }
    printf("\n");
}

void print_matrix(uint32_t *matrix, size_t size) {
    for (int i = 0; i < size; i++) {
        printf("%08x ", matrix[i]);
        if ((i + 1) % 4 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

void print_msg(uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i += 16) {
        printf("%03ld | ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02x ", data[i + j]);
            else
                printf("   ");
        }
        printf("| ");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            if (data[i + j] >= 32 && data[i + j] <= 126) {
                printf("%c", data[i + j]);
            } else {
                printf(".");
            }
        }
        printf("\n");
    }
}

uint32_t pack4(uint8_t *num) {
    uint32_t res = 0;
    res |= (uint32_t)num[0] << 0 * 8;
    res |= (uint32_t)num[1] << 1 * 8;
    res |= (uint32_t)num[2] << 2 * 8;
    res |= (uint32_t)num[3] << 3 * 8;
    return res;
}

void unpack4(uint32_t src, uint8_t *dst) {
    dst[0] = (src >> 0 * 8) & 0xff;
    dst[1] = (src >> 1 * 8) & 0xff;
    dst[2] = (src >> 2 * 8) & 0xff;
    dst[3] = (src >> 3 * 8) & 0xff;
}

uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}