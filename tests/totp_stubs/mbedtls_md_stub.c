/* host 测试用 mbedtls/md 桩实现：测试不会调用 TOTP 计算，全部返回失败。 */
#include "mbedtls/md.h"

const mbedtls_md_info_t *mbedtls_md_info_from_type(mbedtls_md_type_t md_type)
{
    (void)md_type;
    return 0;
}

size_t mbedtls_md_get_size(const mbedtls_md_info_t *md_info)
{
    (void)md_info;
    return 0;
}

int mbedtls_md_hmac(const mbedtls_md_info_t *md_info, const unsigned char *key, size_t keylen,
                    const unsigned char *input, size_t ilen, unsigned char *output)
{
    (void)md_info;
    (void)key;
    (void)keylen;
    (void)input;
    (void)ilen;
    (void)output;
    return -1;
}
