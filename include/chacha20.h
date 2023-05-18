#pragma once

#include <stddef.h>
#include <stdint.h>

void chacha20_serialize(uint32_t out[16], uint8_t key[32], uint8_t nonce[12], uint32_t counter);
void chacha20_qround(uint32_t state[16], size_t a, size_t b, size_t c, size_t d);
void chacha20_inner_block(uint32_t state[16]);
void chacha20_block(uint32_t state[16], uint8_t key[32], uint8_t nonce[12], uint32_t counter);
void chacha20_counter_increment(uint8_t nonce[12], uint32_t *counter);
void chacha20_counter_decrement(uint8_t nonce[12], uint32_t *counter);
void chacha20_counter(uint32_t state[16]);
void chacha20_encrypt(uint8_t key[32], uint8_t nonce[12], uint32_t *counter, uint8_t *position, uint8_t *plaintext, size_t l);
void chacha20_test();

void chacha20_test_a1_block_vector(size_t id, uint8_t key[32], uint8_t nonce[12], uint32_t counter);
void chacha20_test_a1_block_vectors();
void chacha20_test_a2_encrypt_vector(size_t id, uint8_t key[32], uint8_t nonce[12], uint32_t counter, uint8_t *plaintext, size_t l);
void chacha20_test_a2_encrypt_vectors();
