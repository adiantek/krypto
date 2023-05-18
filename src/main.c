#include <poly1305.h>
#include <chacha20.h>
#include <chacha20poly1305.h>

int main() {
    // chacha20_test();
    // poly1305_test();
    // poly1305_key_test();
    // chacha20_aead_test();
    chacha20_test_encrypt_vectors();
    return 0;
}
