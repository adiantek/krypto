#include <chacha20.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utils.h>

// #define CHACHA20_DEBUG

void chacha20_serialize(uint32_t out[16], uint8_t key[32], uint8_t nonce[12], uint32_t counter) {
    uint8_t *magic = (uint8_t *)"expand 32-byte k";
    for (int i = 0; i < 4; i++) {
        out[i] = pack4(magic + i * 4);
    }
    for (int i = 0; i < 8; i++) {
        out[i + 4] = pack4(key + i * 4);
    }
    out[12] = counter;
    for (int i = 0; i < 3; i++) {
        out[i + 13] = pack4(nonce + i * 4);
    }
}

void chacha20_qround(uint32_t state[16], size_t a, size_t b, size_t c, size_t d) {
    state[a] += state[b];
    state[d] = rotl32(state[d] ^ state[a], 16);

    state[c] += state[d];
    state[b] = rotl32(state[b] ^ state[c], 12);

    state[a] += state[b];
    state[d] = rotl32(state[d] ^ state[a], 8);

    state[c] += state[d];
    state[b] = rotl32(state[b] ^ state[c], 7);
}

void chacha20_inner_block(uint32_t state[16]) {
    chacha20_qround(state, 0, 4, 8, 12);
    chacha20_qround(state, 1, 5, 9, 13);
    chacha20_qround(state, 2, 6, 10, 14);
    chacha20_qround(state, 3, 7, 11, 15);
    chacha20_qround(state, 0, 5, 10, 15);
    chacha20_qround(state, 1, 6, 11, 12);
    chacha20_qround(state, 2, 7, 8, 13);
    chacha20_qround(state, 3, 4, 9, 14);
}

void chacha20_block(uint32_t state[16], uint8_t key[32], uint8_t nonce[12], uint32_t counter) {
    chacha20_serialize(state, key, nonce, counter);
#ifdef CHACHA20_DEBUG
    printf("state:\n");
    print_matrix(state, 16);
#endif
    uint32_t working_state[16];
    for (int i = 0; i < 16; i++) {
        working_state[i] = state[i];
    }
    for (int i = 0; i < 10; i++) {
        chacha20_inner_block(working_state);
    }
    for (int i = 0; i < 16; i++) {
        state[i] += working_state[i];
    }
}

void chacha20_counter_increment(uint8_t nonce[12], uint32_t *counter) {
    (*counter)++;
    if (*counter == 0) {
        uint32_t *counter_state = (uint32_t *)nonce;
        (*counter_state)++;
    }
}

void chacha20_counter_decrement(uint8_t nonce[12], uint32_t *counter) {
    if (*counter == 0) {
        uint32_t *counter_state = (uint32_t *)nonce;
        (*counter_state)--;
    }
    (*counter)--;
}

void chacha20_encrypt(uint8_t key[32], uint8_t nonce[12], uint32_t *counter, uint8_t *position, uint8_t *plaintext, size_t l) {
    uint32_t state[16];
    uint8_t *key_stream = (uint8_t *)state;
    if (*position < 64) {
        chacha20_counter_decrement(nonce, counter);
        chacha20_block(state, key, nonce, *counter);
        chacha20_counter_increment(nonce, counter);
    }
    for (size_t j = 0; j < l; j++) {
        if (*position >= 64) {
            chacha20_block(state, key, nonce, *counter);
            chacha20_counter_increment(nonce, counter);
#ifdef CHACHA20_DEBUG
            print_hex("key_stream", key_stream, 64);
#endif
            *position = 0;
        }
        plaintext[j] ^= key_stream[*position];
        (*position)++;
    }
}

void chacha20_test() {
    printf("========== CHACHA20 TEST ==========\n");
    uint8_t key[32] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
    uint8_t nonce[12] = "\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x00";
    uint32_t counter = 1;

    print_hex("key", key, 32);
    print_hex("nonce", nonce, 12);
    printf("counter: %d\n", counter);

    uint8_t plaintext[] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    size_t plaintext_length = 114;
    printf("Plaintext Sunscreen:\n");
    print_msg(plaintext, plaintext_length);

    uint8_t position = 64;
    for (int i = 0; i < 114; i++) {
        chacha20_encrypt(key, nonce, &counter, &position, plaintext + i, 1);
    }
    printf("Ciphertext Sunscreen:\n");
    print_msg(plaintext, plaintext_length);
    printf("\n");
}

void chacha20_test_a1_block_vector(size_t id, uint8_t key[32], uint8_t nonce[12], uint32_t counter) {
    printf("Test Vector #%ld:\n", id);
    printf("==============\n");
    printf("\n");
    uint32_t state[16];
    chacha20_block(state, key, nonce, counter);

    printf("Key:\n");
    print_msg(key, 32);
    printf("\n");
    printf("Nonce:\n");
    print_msg(nonce, 12);
    printf("\n");
    printf("Block Counter: %d\n", counter);
    printf("\n");
    printf("ChaCha state at the end:\n");
    print_matrix(state, 16);
    printf("Keystream:\n");
    print_msg((uint8_t *)state, 64);
    printf("\n");
    printf("\n");
}

void chacha20_test_a1_block_vectors() {
    chacha20_test_a1_block_vector(1,
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                  0);
    chacha20_test_a1_block_vector(2,
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                  1);
    chacha20_test_a1_block_vector(3,
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                  1);
    chacha20_test_a1_block_vector(4,
                                  "\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                  2);
    chacha20_test_a1_block_vector(5,
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                  "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
                                  0);
}

void chacha20_test_a2_encrypt_vector(size_t id, uint8_t key[32], uint8_t nonce[12], uint32_t counter, uint8_t *plaintext, size_t l) {
    printf("Test Vector #%ld:\n", id);
    printf("==============\n");
    printf("\n");
    uint32_t state[16];
    chacha20_block(state, key, nonce, counter);

    printf("Key:\n");
    print_msg(key, 32);
    printf("\n");
    printf("Nonce:\n");
    print_msg(nonce, 12);
    printf("\n");
    printf("Initial Block Counter: %d\n", counter);
    printf("\n");
    printf("Plaintext:\n");
    print_msg(plaintext, l);
    printf("\n");
    uint8_t position = 64;
    uint8_t *ciphertext = (uint8_t *)malloc(l);
    if (!ciphertext) {
        printf("malloc failed\n");
        exit(1);
    }
    memcpy(ciphertext, plaintext, l);
    chacha20_encrypt(key, nonce, &counter, &position, ciphertext, l);
    printf("Ciphertext:\n");
    print_msg(ciphertext, l);
    free(ciphertext);
    printf("\n");
    printf("\n");
}

void chacha20_test_a2_encrypt_vectors() {
    chacha20_test_a2_encrypt_vector(1,
                                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                    0,
                                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                    64);
    chacha20_test_a2_encrypt_vector(2,
                                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01",
                                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
                                    1,
                                    "Any submission to the IETF intended by the Contributor for publi"
                                    "cation as all or part of an IETF Internet-Draft or RFC and any s"
                                    "tatement made within the context of an IETF activity is consider"
                                    "ed an \"IETF Contribution\". Such statements include oral statem"
                                    "ents in IETF sessions, as well as written and electronic communi"
                                    "cations made at any time or place, which are addressed to",
                                    375);
    chacha20_test_a2_encrypt_vector(3,
                                    "\x1c\x92\x40\xa5\xeb\x55\xd3\x8a\xf3\x33\x88\x86\x04\xf6\xb5\xf0"
                                    "\x47\x39\x17\xc1\x40\x2b\x80\x09\x9d\xca\x5c\xbc\x20\x70\x75\xc0",
                                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02",
                                    42,
                                    "'Twas brillig, and the slithy toves\nDid gyre and gimble in the "
                                    "wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrab"
                                    "e.",
                                    127);
}