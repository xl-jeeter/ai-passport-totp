#include "totp_http_proto.h"

#include <string.h>

#include "totp_core.h"

/* ASCII 大小写不敏感比较（避免依赖 POSIX 的 strcasecmp，保持 host 可编译）。 */
static bool ieq(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {
        char ca = (*a >= 'A' && *a <= 'Z') ? (char)(*a - 'A' + 'a') : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? (char)(*b - 'A' + 'a') : *b;
        if (ca != cb) {
            return false;
        }
        a++;
        b++;
    }
    return *a == *b;
}

int totp_proto_account_index(const char *uri, int count)
{
    if (uri == NULL || count <= 0) {
        return -1;
    }
    const char *slash = strrchr(uri, '/');
    if (slash == NULL || slash[1] == '\0') {
        return -1;
    }
    const char *p = slash + 1;
    if (*p < '0' || *p > '9') {
        return -1;
    }
    long value = 0;
    while (*p >= '0' && *p <= '9') {
        value = value * 10 + (*p - '0');
        if (value >= count) {
            return -1;
        }
        p++;
    }
    /* 下标后面只允许是结尾或查询串（本接口不会带，但解析保持健壮） */
    if (*p != '\0' && *p != '?') {
        return -1;
    }
    return (int)value;
}

int totp_proto_algo_from_name(const char *name)
{
    if (name == NULL || name[0] == '\0') {
        return 0;
    }
    if (ieq(name, "SHA1")) {
        return 0;
    }
    if (ieq(name, "SHA256")) {
        return 1;
    }
    if (ieq(name, "SHA512")) {
        return 2;
    }
    return -1;
}

const char *totp_proto_algo_name(int algo)
{
    switch (algo) {
    case 1:
        return "SHA256";
    case 2:
        return "SHA512";
    default:
        return "SHA1";
    }
}

bool totp_proto_account_fields(const char *name, const char *secret,
                               int digits, int period, int algo,
                               int *out_digits, int *out_period, int *out_algo)
{
    if (name == NULL || name[0] == '\0' || secret == NULL || secret[0] == '\0') {
        return false;
    }
    if (digits == 0) {
        digits = 6;
    }
    if (period == 0) {
        period = 30;
    }
    if (algo == -1) {
        algo = 0;
    }
    if (digits < 6 || digits > 8 || period < 10 || period > 120 || algo < 0 || algo > 2) {
        return false;
    }
    uint8_t key[96];
    size_t key_len = 0;
    if (base32_decode(secret, key, sizeof(key), &key_len) != 0 || key_len == 0) {
        return false;
    }
    if (out_digits != NULL) {
        *out_digits = digits;
    }
    if (out_period != NULL) {
        *out_period = period;
    }
    if (out_algo != NULL) {
        *out_algo = algo;
    }
    return true;
}
