#ifndef __ECDSA_H__
#define __ECDSA_H__

#include <stdint.h>

// returning zero means error

// byte[32] -> byte[64]
int ecdsa_secret_to_public(const uint8_t *secretkey, uint8_t *publickey);

// byte[32] x byte[32] -> byte[64]
int ecdsa_p256_rfc6979_sign(
    const uint8_t *secretkey, const uint8_t *hashedmsg, uint8_t *signature);

// byte[32] x byte[32] -> byte[8 ~ 72]
int ecdsa_p256_rfc6979_sign_asn1(
    const uint8_t *secretkey, const uint8_t *hashedmsg, uint8_t *signature_asn1);

#endif
