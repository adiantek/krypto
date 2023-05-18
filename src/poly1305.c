#include <gmp.h>
#include <poly1305.h>
#include <stdio.h>
#include <utils.h>

// #define POLY1305_DEBUG

void poly1305_clamp(uint8_t km[32]) {
    uint8_t *r = km;
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;
}

void poly1305_mac(uint8_t out[16], uint8_t km[32], uint8_t *m,
                         size_t l) {
    size_t j;
    mpz_t rbar, h, c, p;
    mpz_inits(rbar, h, c, p, NULL);

#ifdef POLY1305_DEBUG
    print_hex("Key Material", km, 32);
#endif

    poly1305_clamp(km);
    uint8_t *r = km;
    uint8_t *s = km + 16;
    mpz_import(rbar, 16, -1, 1, 0, 0, r);

#ifdef POLY1305_DEBUG
    print_hex("s as an octet string", s, 16);
    mpz_import(c, 16, -1, 1, 0, 0, s);
    print_num("s as a 128-bit number", c);
    print_hex("r before clamping", r, 16);
    print_num("Clamped r as a number", rbar);

    printf("Message to be Authenticated:\n");
    print_msg(m, l);
    size_t blockIndex = 1;
#endif

    mpz_set_ui(h, 0);
    mpz_set_ui(p, 1);
    mpz_mul_2exp(p, p, 130);
    mpz_sub_ui(p, p, 5);
    while (l > 0) {
#ifdef POLY1305_DEBUG
        printf("\nBlock #%ld\n", blockIndex++);
#endif
        if (l < 16) {
            j = l;
        } else {
            j = 16;
        }
        mpz_import(c, j, -1, 1, 0, 0, m);
#ifdef POLY1305_DEBUG
        print_num("Acc", h);
        print_num("Block", c);
#endif
        m += j;
        l -= j;
        mpz_add(h, h, c);
        mpz_set_ui(c, 1);
        mpz_mul_2exp(c, c, 8 * j);
        mpz_add(h, h, c);
#ifdef POLY1305_DEBUG
        print_num("Acc + Block", h);
#endif
        mpz_mul(h, h, rbar);
#ifdef POLY1305_DEBUG
        print_num("(Acc + Block) * r", h);
#endif
        mpz_tdiv_r(h, h, p);
#ifdef POLY1305_DEBUG
        print_num("Acc = ((Acc + Block) * r) % P", h);
#endif
    }
    mpz_import(c, 16, -1, 1, 0, 0, s);
    mpz_add(h, h, c);
#ifdef POLY1305_DEBUG
    printf("\n");
    print_num("Acc + s", h);
#endif
    for (j = 0; j < 16; j++) {
        out[j] = mpz_tdiv_q_ui(h, h, 256);
    }
#ifdef POLY1305_DEBUG
    print_hex("Tag", out, 16);
#endif
    mpz_clears(rbar, h, c, p, NULL);
}

void poly1305_test() {
    printf("========== POLY1305 TEST ==========\n");
    uint8_t out[16];
    uint8_t km[] =
        "\x85\xd6\xbe\x78\x57\x55\x6d\x33\x7f\x44\x52\xfe\x42\xd5\x06\xa8"
        "\x01\x03\x80\x8a\xfb\x0d\xb2\xfd\x4a\xbf\xf6\xaf\x41\x49\xf5\x1b";

    print_hex("Key Material", km, 32);

    uint8_t *msg = (uint8_t *) "Cryptographic Forum Research Group";
    size_t msg_len = 34;
    
    printf("Message to be Authenticated:\n");
    print_msg(msg, msg_len);

    poly1305_mac(out, km, msg, msg_len);

    print_hex("tag", out, 16);
    printf("\n");
}
