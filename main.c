#include "ecdsa.h"
#include <stdio.h>

int main(void)
{
    int ret;
    const uint8_t secretkey[32] = {
            0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c,
            0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93, 0x4e, 0x50, 0xc3, 0xdb,
            0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f,
            0x67, 0x21 };
    const uint8_t hashedmsg[32] = {
            0xaf, 0x2b, 0xdb, 0xe1, 0xaa, 0x9b, 0x6e, 0xc1, 0xe2, 0xad,
            0xe1, 0xd6, 0x94, 0xf4, 0x1f, 0xc7, 0x1a, 0x83, 0x1d, 0x02,
            0x68, 0xe9, 0x89, 0x15, 0x62, 0x11, 0x3d, 0x8a, 0x62, 0xad,
            0xd1, 0xbf };
    uint8_t publickey[64];
    uint8_t signature[72];

    ret = ecdsa_secret_to_public(secretkey, publickey);
    if (ret) {
        int i;
        for (i = 0; i < 64; ++i) {
            printf("%02x", publickey[i]);
        }
        printf("\n");
    }

    ret = ecdsa_p256_rfc6979_sign(secretkey, hashedmsg, signature);
    if (ret) {
        int i;
        for (i = 0; i < 64; ++i) {
            printf("%02x", signature[i]);
        }
        printf("\n");
    }

    ret = ecdsa_p256_rfc6979_sign_asn1(secretkey, hashedmsg, signature);
    if (ret) {
        int i;
        for (i = 0; i < ret; ++i) {
            printf("%02x", signature[i]);
        }
        printf("\n");
    }

    return 0;
}
