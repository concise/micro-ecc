#include "uECC.h"
#include "sha256.h"
#include <stdint.h>
#include <string.h>

typedef struct {
    uECC_HashContext ctx;
    sha256_context_t sha256_ctx;
} uECC_SHA256;

static void uECC_sha256_init_hash(uECC_HashContext *base)
{
    uECC_SHA256 *wrapper = (uECC_SHA256 *) base;
    sha256_starts(&wrapper->sha256_ctx);
}

static void uECC_sha256_update_hash(
    uECC_HashContext *base, const uint8_t *message, unsigned message_size)
{
    uECC_SHA256 *wrapper = (uECC_SHA256 *) base;
    sha256_update(&wrapper->sha256_ctx, message_size, message);
}

static void uECC_sha256_finish_hash(
    uECC_HashContext *base, uint8_t *hash_result)
{
    uECC_SHA256 *wrapper = (uECC_SHA256 *) base;
    sha256_finish(&wrapper->sha256_ctx, hash_result);
}

int ecdsa_secret_to_public(const uint8_t *secretkey, uint8_t *publickey)
{
    return uECC_compute_public_key(secretkey, publickey);
}

int ecdsa_p256_rfc6979_sign(
    const uint8_t *secretkey, const uint8_t *hashedmsg, uint8_t *signature)
{
    uint8_t uECC_hash_working_area[128];
    uECC_SHA256 uecc_sha256;

    uecc_sha256.ctx.init_hash   = &uECC_sha256_init_hash;
    uecc_sha256.ctx.update_hash = &uECC_sha256_update_hash;
    uecc_sha256.ctx.finish_hash = &uECC_sha256_finish_hash;
    uecc_sha256.ctx.block_size  = 64;
    uecc_sha256.ctx.result_size = 32;
    uecc_sha256.ctx.tmp         = uECC_hash_working_area;

    if (!secretkey || !hashedmsg || !signature) {
        return 0;
    }

    return uECC_sign_deterministic(secretkey, hashedmsg,
                                   &uecc_sha256.ctx, signature);
}

static void write_uint256_to_asn1integer(
    const uint8_t bytes[32],
    uint8_t asn1_buffer[35])
{
    int i;

    for (i = 0; i <= 31; ++i) {
        if (bytes[i] >= 0x80) {
            // This byte is 128 ~ 255
            asn1_buffer[0] = 0x02;
            asn1_buffer[1] = 1 + (32 - i);
            asn1_buffer[2] = 0x00;
            memcpy(&asn1_buffer[3], &bytes[i], 32 - i);
            return;
        } else if (bytes[i] > 0x00) {
            // This byte is 1 ~ 127
            asn1_buffer[0] = 0x02;
            asn1_buffer[1] = 32 - i;
            memcpy(&asn1_buffer[2], &bytes[i], 32 - i);
            return;
        }
    }

    // bytes: 0000000000000000000000000000000000000000000000000000000000000000
    asn1_buffer[0] = 0x02;
    asn1_buffer[1] = 1;
    asn1_buffer[2] = 0x00;
}

// An ECDSA public key on P-256 curve will be encoded in uncompressed form as
// 65 octects:  { 0x04, Qx, Qy }
//
// An ECDSA signature on P-256 curve will be encoded as an ASN.1 sequence
// that contains at most 72 octets:
//
//      BYTE LENGTH     VALUE               TYPE
//      -----------     ---------------     --------------
//      1               0x30 (SEQUENCE)     tag
//      1               rlen + slen + 4     length <= 70
//
//      1               0x02 (INTEGER)      tag
//      1               rlen                length <= 33
//      rlen            r                   signed integer
//
//      1               0x02 (INTEGER)      tag
//      1               slen                length <= 33
//      slen            s                   signed integer
//
//      Note:   Both r and s are integers modulo the 256-bit N; when the
//              highest bit is 1 (the highest byte >= 0x80), an additional zero
//              byte must be prefixed, or the integer will be viewed as a
//              negative number.
//
//      N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
//

static void ecdsa_p256_encode_signature(
    const uint8_t *signature_64octets,
    uint8_t *output_asn1_sequence)
{
    const uint8_t *r = signature_64octets;
    const uint8_t *s = signature_64octets + 32;
    uint8_t seqlen;
    uint8_t rlen;
    uint8_t slen;

    if (!signature_64octets || !output_asn1_sequence) {
        return;
    }

    write_uint256_to_asn1integer(r, &output_asn1_sequence[2]);
    rlen = output_asn1_sequence[3];

    write_uint256_to_asn1integer(s, &output_asn1_sequence[rlen + 4]);
    slen = output_asn1_sequence[rlen + 5];

    seqlen = rlen + slen + 4;
    output_asn1_sequence[1] = seqlen;
    output_asn1_sequence[0] = 0x30;
}

int ecdsa_p256_rfc6979_sign_asn1(
    const uint8_t *secretkey, const uint8_t *hashedmsg, uint8_t *signature_asn1)
{
    uint8_t signature[64];
    int ret;

    if (!signature_asn1) {
        return 0;
    }

    ret = ecdsa_p256_rfc6979_sign(secretkey, hashedmsg, signature);

    if (!ret) {
        return 0;
    }

    ecdsa_p256_encode_signature(signature, signature_asn1);
    return 2 + signature_asn1[1];
}
