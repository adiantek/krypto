#pragma once

#include <stddef.h>
#include <stdint.h>

void poly1305_key_gen(uint8_t out[32], uint8_t key[32], uint8_t nonce[12]);
void poly1305_key_test();

void chacha20_aead_encrypt(uint8_t *aad, size_t aad_len, uint8_t key[32],
                           uint8_t iv[8], uint32_t constant,
                           uint8_t *plaintext, size_t plaintext_len, uint8_t tag[16]);
void chacha20_aead_test();
