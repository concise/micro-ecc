#include "uECC.h"
#include "sha256.h"
#include <stdint.h>

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

    return uECC_sign_deterministic(secretkey, hashedmsg,
                                   &uecc_sha256.ctx, signature);
}
