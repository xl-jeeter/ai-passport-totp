#pragma once
/* host 测试用最小 mbedtls/md.h 桩：只为让 totp_core.c 通过编译。
 * 测试只调用 base32_decode，totp_code 不会被执行（桩返回失败）。 */
#include <stddef.h>

typedef enum {
    MBEDTLS_MD_NONE = 0,
    MBEDTLS_MD_SHA1,
    MBEDTLS_MD_SHA256,
    MBEDTLS_MD_SHA512,
} mbedtls_md_type_t;

typedef struct mbedtls_md_info_t mbedtls_md_info_t;

const mbedtls_md_info_t *mbedtls_md_info_from_type(mbedtls_md_type_t md_type);
size_t mbedtls_md_get_size(const mbedtls_md_info_t *md_info);
int mbedtls_md_hmac(const mbedtls_md_info_t *md_info, const unsigned char *key, size_t keylen,
                    const unsigned char *input, size_t ilen, unsigned char *output);
