#pragma once

#include <stddef.h>
#include <stdint.h>

void poly1305_clamp(uint8_t km[32]);
void poly1305_mac(uint8_t out[16], uint8_t km[32], uint8_t *m, size_t l);
void poly1305_test();