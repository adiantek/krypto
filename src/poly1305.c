#include <gmp.h>
#include <poly1305.h>
#include <stdio.h>
#include <string.h>
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

    uint8_t *msg = (uint8_t *)"Cryptographic Forum Research Group";
    size_t msg_len = 34;

    printf("Message to be Authenticated:\n");
    print_msg(msg, msg_len);

    poly1305_mac(out, km, msg, msg_len);

    print_hex("tag", out, 16);
    printf("\n");
}

void poly1305_test_a3_msg_vector(size_t id, uint8_t key[32], uint8_t *m, size_t l) {
    uint8_t key_rw[32];
    memcpy(key_rw, key, 32);

    printf("Test Vector #%ld:\n", id);
    printf("==============\n");
    printf("\n");

    printf("One-time Poly1305 Key:\n");
    print_msg(key, 32);
    printf("\n");
    printf("Text to MAC:\n");
    print_msg(m, l);
    printf("\n");

    uint8_t tag[16];
    poly1305_mac(tag, key_rw, m, l);

    printf("Tag:\n");
    print_msg(tag, 16);
    printf("\n");
    printf("\n");
}

void poly1305_test_a3_msg_vectors() {
    poly1305_test_a3_msg_vector(1,
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                64);
    poly1305_test_a3_msg_vector(2,
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                "\x36\xe5\xf6\xb5\xc5\xe0\x60\x70\xf0\xef\xca\x96\x22\x7a\x86\x3e",
                                "Any submission to the IETF intended by the Contributor for publi"
                                "cation as all or part of an IETF Internet-Draft or RFC and any s"
                                "tatement made within the context of an IETF activity is consider"
                                "ed an \"IETF Contribution\". Such statements include oral statem"
                                "ents in IETF sessions, as well as written and electronic communi"
                                "cations made at any time or place, which are addressed to",
                                375);
    poly1305_test_a3_msg_vector(3,
                                "\x36\xe5\xf6\xb5\xc5\xe0\x60\x70\xf0\xef\xca\x96\x22\x7a\x86\x3e"
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                "Any submission to the IETF intended by the Contributor for publi"
                                "cation as all or part of an IETF Internet-Draft or RFC and any s"
                                "tatement made within the context of an IETF activity is consider"
                                "ed an \"IETF Contribution\". Such statements include oral statem"
                                "ents in IETF sessions, as well as written and electronic communi"
                                "cations made at any time or place, which are addressed to",
                                375);
    poly1305_test_a3_msg_vector(4,
                                "\x1c\x92\x40\xa5\xeb\x55\xd3\x8a\xf3\x33\x88\x86\x04\xf6\xb5\xf0"
                                "\x47\x39\x17\xc1\x40\x2b\x80\x09\x9d\xca\x5c\xbc\x20\x70\x75\xc0",
                                "'Twas brillig, and the slithy toves\nDid gyre and gimble in the "
                                "wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrab"
                                "e.",
                                127);
    poly1305_test_a3_msg_vector(5,
                                "\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                                16);
    poly1305_test_a3_msg_vector(6,
                                "\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                                "\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                16);
    poly1305_test_a3_msg_vector(7,
                                "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                                "\xF0\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                                "\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                48);
    poly1305_test_a3_msg_vector(8,
                                "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
                                "\xFB\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE\xFE"
                                "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01",
                                48);
    poly1305_test_a3_msg_vector(9,
                                "\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                "\xFD\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
                                16);
    poly1305_test_a3_msg_vector(10,
                                "\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00"
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                "\xE3\x35\x94\xD7\x50\x5E\x43\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
                                "\x33\x94\xD7\x50\x5E\x43\x79\xCD\x01\x00\x00\x00\x00\x00\x00\x00"
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                64);
    poly1305_test_a3_msg_vector(11,
                                "\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00"
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                "\xE3\x35\x94\xD7\x50\x5E\x43\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
                                "\x33\x94\xD7\x50\x5E\x43\x79\xCD\x01\x00\x00\x00\x00\x00\x00\x00"
                                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                48);
}