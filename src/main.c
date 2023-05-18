#include <poly1305.h>
#include <chacha20.h>
#include <chacha20poly1305.h>

int main() {
    chacha20_test();
    poly1305_test();
    poly1305_key_test();
    chacha20_aead_test();
    chacha20_test_a1_block_vectors();
    chacha20_test_a2_encrypt_vectors();
    poly1305_test_a3_msg_vectors();
    poly1305_test_a4_keygens();
    return 0;
}
