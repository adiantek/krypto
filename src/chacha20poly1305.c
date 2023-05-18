#include <chacha20.h>
#include <chacha20poly1305.h>
#include <poly1305.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utils.h>

// #define CHACHA20_POLY1305_DEBUG

void poly1305_key_gen(uint8_t out[32], uint8_t key[32], uint8_t nonce[12]) {
    uint32_t counter = 0;
    uint32_t state[16];
    chacha20_block(state, key, nonce, counter);
    uint8_t *block = (uint8_t *)state;
    for (size_t i = 0; i < 32; i++) {
        out[i] = block[i];
    }
}

void poly1305_key_test() {
    printf("========== POLY1305 KEY TEST ==========\n");

    uint8_t key[32] =
        "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
        "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f";
    uint8_t nonce[12] = "\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07";

    printf("Key:\n");
    print_msg(key, 32);
    printf("Nonce:\n");
    print_msg(nonce, 12);

    uint8_t out[32];
    poly1305_key_gen(out, key, nonce);
    printf("Output:\n");
    print_msg(out, 32);
    printf("\n");
}

void chacha20_aead_encrypt(uint8_t *aad, size_t aad_len, uint8_t key[32],
                           uint8_t iv[8], uint32_t constant,
                           uint8_t *plaintext, size_t plaintext_len, uint8_t tag[16]) {
    uint8_t nonce[12];
    for (size_t i = 0; i < 8; i++) {
        nonce[i + 4] = iv[i];
    }
    for (size_t i = 0; i < 4; i++) {
        nonce[i] = ((uint8_t *)&constant)[i];
    }
    uint8_t otk[32];
    poly1305_key_gen(otk, key, nonce);
#ifdef CHACHA20_POLY1305_DEBUG
    printf("Poly1305 Key:\n");
    print_msg(otk, 32);
#endif
    uint32_t counter = 1;
    uint8_t position = 64;
    chacha20_encrypt(key, nonce, &counter, &position, plaintext, plaintext_len);

    size_t aad_padding = 16 - (aad_len % 16);
    size_t plaintext_padding = 16 - (plaintext_len % 16);

    size_t mac_len = aad_len + aad_padding + plaintext_len + plaintext_padding + 16;
    uint8_t *mac_data = (uint8_t *)malloc(mac_len);
    if (!mac_data) {
        printf("malloc failed\n");
        exit(1);
    }

    uint8_t *d = mac_data;
    for (size_t i = 0; i < aad_len; i++)
        *d++ = aad[i];
    for (size_t i = 0; i < aad_padding; i++)
        *d++ = 0;
    for (size_t i = 0; i < plaintext_len; i++)
        *d++ = plaintext[i];
    for (size_t i = 0; i < plaintext_padding; i++)
        *d++ = 0;

    uint64_t *mac64 = (uint64_t *)d;
    *mac64++ = aad_len;
    *mac64++ = plaintext_len;

#ifdef CHACHA20_POLY1305_DEBUG
    printf("AEAD Construction for Poly1305:\n");
    print_msg(mac_data, mac_len);
#endif

    poly1305_mac(tag, otk, mac_data, mac_len);
    free(mac_data);
}

void chacha20_aead_test() {
    printf("========== CHACHA20 AEAD TEST ==========\n");

    uint8_t plaintext[] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    size_t plaintext_length = 114;
    uint8_t *aad = "\x50\x51\x52\x53\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7";
    size_t aad_len = 12;
    uint8_t key[32] =
        "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f"
        "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f";
    uint8_t iv[8] = "\x40\x41\x42\x43\x44\x45\x46\x47";
    uint32_t constant = 0x00000007;

    printf("Plaintext:\n");
    print_msg(plaintext, plaintext_length);
    printf("AAD:\n");
    print_msg(aad, aad_len);
    printf("Key:\n");
    print_msg(key, 32);
    printf("IV:\n");
    print_msg(iv, 8);
    printf("32-bit fixed-common part:\n");
    print_msg((uint8_t *)&constant, 4);

    uint8_t tag[16];

    chacha20_aead_encrypt(aad, aad_len, key, iv, constant, plaintext, plaintext_length, tag);

    printf("Tag:\n");
    print_msg(tag, 16);
}

void poly1305_test_a4_keygen(size_t id, uint8_t key[32], uint8_t nonce[12]) {
    uint8_t key_rw[32];
    memcpy(key_rw, key, 32);

    printf("Test Vector #%ld:\n", id);
    printf("==============\n");
    printf("\n");
    printf("The key:\n");
    print_msg(key_rw, 32);
    printf("\n");
    printf("The nonce:\n");
    print_msg(nonce, 12);
    printf("\n");

    uint8_t out[32];
    poly1305_key_gen(out, key_rw, nonce);
    printf("Poly1305 one-time key:\n");
    print_msg(out, 32);
    printf("\n");
    printf("\n");
}

void poly1305_test_a4_keygens() {
    poly1305_test_a4_keygen(1,
                            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    poly1305_test_a4_keygen(2,
                            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02");
    poly1305_test_a4_keygen(3,
                            "\x1c\x92\x40\xa5\xeb\x55\xd3\x8a\xf3\x33\x88\x86\x04\xf6\xb5\xf0"
                            "\x47\x39\x17\xc1\x40\x2b\x80\x09\x9d\xca\x5c\xbc\x20\x70\x75\xc0",
                            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02");
}
