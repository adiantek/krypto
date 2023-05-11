#include <gmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct poly1305 {
  mpz_t r;
  mpz_t s;
  mpz_t a;
  mpz_t p;
  mpz_t x;
} poly1305;

void poly1305_init(poly1305 *ctx, const char *key);
void poly1305_free(poly1305 *ctx);
char *poly1305_create_tag(poly1305 *ctx, const char *data, size_t data_len);

void print_num(char *name, mpz_t num);
void swap_endian(const char *num, char *res);
uint32_t rotl32(uint32_t x, int n);
uint32_t pack4(const uint8_t *a);
void unpack4(uint32_t src, uint8_t *dst);

void print_num(char *name, mpz_t num) {
  char *str = mpz_get_str(NULL, 16, num);
  printf("%s: %s\n", name, str);
  free(str);
}

void swap_endian(const char *num, char *res) {
  size_t len = strlen(num);
  for (int i = 0; i < len / 2; i++) {
    res[i * 2] = num[len - i * 2 - 2];
    res[i * 2 + 1] = num[len - i * 2 - 1];
  }
  res[len] = 0;
}

uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

uint32_t pack4(const uint8_t *a) {
  uint32_t res = 0;
  res |= (uint32_t)a[0] << 0 * 8;
  res |= (uint32_t)a[1] << 1 * 8;
  res |= (uint32_t)a[2] << 2 * 8;
  res |= (uint32_t)a[3] << 3 * 8;
  return res;
}

void unpack4(uint32_t src, uint8_t *dst) {
  dst[0] = (src >> 0 * 8) & 0xff;
  dst[1] = (src >> 1 * 8) & 0xff;
  dst[2] = (src >> 2 * 8) & 0xff;
  dst[3] = (src >> 3 * 8) & 0xff;
}

void poly1305_init(poly1305 *ctx, const char *key) {
  printf("Key Material: %s\n", key);

  mpz_init(ctx->r);
  mpz_init(ctx->s);
  mpz_init(ctx->a);
  mpz_init(ctx->p);
  mpz_init(ctx->x);

  mpz_set_ui(ctx->a, 0);

  char k[33];
  char n[33];
  memcpy(k, key, 32);
  memcpy(n, key + 32, 32);
  k[32] = 0;
  n[32] = 0;

  char k1[33];
  char n1[33];
  swap_endian(k, k1);
  swap_endian(n, n1);

  mpz_set_str(ctx->r, k1, 16);
  mpz_set_str(ctx->s, n1, 16);
  mpz_set_str(ctx->p, "0ffffffc0ffffffc0ffffffc0fffffff", 16);
  mpz_and(ctx->r, ctx->r, ctx->p);
  mpz_set_str(ctx->p, "3fffffffffffffffffffffffffffffffb", 16);
  mpz_set_str(ctx->x, "ffffffffffffffffffffffffffffffff", 16);

  printf("s as an octet string: %s\n", n);
  print_num("s as a 128-bit number", ctx->s);

  printf("r as an octet string: %s\n", k);
  print_num("Clamped r as a number", ctx->r);
}

void poly1305_free(poly1305 *ctx) {
  mpz_clear(ctx->r);
  mpz_clear(ctx->s);
  mpz_clear(ctx->a);
  mpz_clear(ctx->p);
  mpz_clear(ctx->x);
}

char *poly1305_create_tag(poly1305 *ctx, const char *data, size_t data_len) {
  mpz_t n;
  mpz_init(n);

  for (size_t i = 0; i < (data_len + 30) / 32; i++) {
    printf("\nBlock #%ld\n\n", i + 1);

    print_num("Acc", ctx->a);
    char tmp[35];
    if (i < data_len / 32) {
      memcpy(tmp, data + i * 32, 32);
      tmp[32] = '0';
      tmp[33] = '1';
      tmp[34] = 0;
    } else {
      memcpy(tmp, data + i * 32, data_len % 32);
      tmp[data_len % 32 + 0] = '0';
      tmp[data_len % 32 + 1] = '1';
      tmp[data_len % 32 + 2] = 0;
    }
    char tmp2[35];
    swap_endian(tmp, tmp2);

    mpz_set_str(n, tmp2, 16);
    print_num("Block with 0x01 byte", n);

    mpz_add(ctx->a, ctx->a, n);
    print_num("Acc + block", ctx->a);

    mpz_mul(ctx->a, ctx->a, ctx->r);
    print_num("(Acc+Block) * r", ctx->a);

    mpz_mod(ctx->a, ctx->a, ctx->p);
    print_num("Acc = ((Acc+Block)*r) % P", ctx->a);
  }
  mpz_add(ctx->a, ctx->a, ctx->s);
  print_num("\nAcc + s", ctx->a);

  mpz_and(ctx->a, ctx->a, ctx->x);

  mpz_clear(n);

  char tmp[33];
  char *tmp2 = malloc(33);
  mpz_get_str(tmp, 16, ctx->a);
  swap_endian(tmp, tmp2);
  printf("Tag: %s\n", tmp2);
  return tmp2;
}

int main() {
  poly1305 ctx;
  poly1305_init(
      &ctx, "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");

  const char *msg =
      "43727970746f6772617068696320466f72756d2052657365617263682047726f7570";

  char *tag = poly1305_create_tag(&ctx, msg, strlen(msg));
  // printf("%s\n", tag);
  free(tag);

  poly1305_free(&ctx);
  return 0;
}
