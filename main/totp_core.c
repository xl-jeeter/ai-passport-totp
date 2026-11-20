#include "totp_core.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "mbedtls/md.h"

static const char *TAG = "totp";

static int base32_value(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a';
    }
    if (c >= '2' && c <= '7') {
        return c - '2' + 26;
    }
    return -1;
}

int base32_decode(const char *encoded, uint8_t *out, size_t out_capacity, size_t *out_len)
{
    if (encoded == NULL || out == NULL || out_len == NULL) {
        return -1;
    }
    size_t produced = 0;
    uint32_t buffer = 0;
    int bits = 0;
    for (const char *p = encoded; *p != '\0'; p++) {
        if (*p == '=' || isspace((unsigned char)*p)) {
            continue;
        }
        int value = base32_value(*p);
        if (value < 0) {
            return -1;
        }
        buffer = (buffer << 5) | (uint32_t)value;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            if (produced >= out_capacity) {
                return -1;
            }
            out[produced++] = (uint8_t)((buffer >> bits) & 0xFF);
        }
    }
    *out_len = produced;
    return 0;
}

uint64_t totp_counter(uint64_t unix_time, uint32_t period)
{
    if (period == 0) {
        period = 30;
    }
    return unix_time / period;
}

uint32_t totp_remaining(uint64_t unix_time, uint32_t period)
{
    if (period == 0) {
        period = 30;
    }
    uint32_t elapsed = (uint32_t)(unix_time % period);
    uint32_t left = period - elapsed;
    return left == 0 ? period : left;
}

int totp_code(const uint8_t *secret, size_t secret_len, uint64_t counter,
              int digits, int algo, char *out, size_t out_capacity)
{
    if (secret == NULL || secret_len == 0 || out == NULL) {
        return -1;
    }
    if (digits < 6 || digits > 8) {
        digits = 6;
    }

    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA1;
    if (algo == 1) {
        md_type = MBEDTLS_MD_SHA256;
    } else if (algo == 2) {
        md_type = MBEDTLS_MD_SHA512;
    }
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(md_type);
    if (info == NULL) {
        return -1;
    }

    uint8_t message[8];
    for (int i = 0; i < 8; i++) {
        message[7 - i] = (uint8_t)((counter >> (8 * i)) & 0xFF);
    }

    uint8_t digest[64];
    if (mbedtls_md_hmac(info, secret, secret_len, message, sizeof(message), digest) != 0) {
        ESP_LOGE(TAG, "HMAC 计算失败");
        return -1;
    }

    int offset = digest[mbedtls_md_get_size(info) - 1] & 0x0F;
    uint32_t binary = ((uint32_t)(digest[offset] & 0x7F) << 24) |
                      ((uint32_t)digest[offset + 1] << 16) |
                      ((uint32_t)digest[offset + 2] << 8) |
                      (uint32_t)digest[offset + 3];

    static const uint32_t powers[] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};
    uint32_t modulo = powers[digits];
    uint32_t value = binary % modulo;

    char formatted[16];
    int written = snprintf(formatted, sizeof(formatted), "%0*u", digits, (unsigned)value);
    if (written <= 0 || (size_t)written >= out_capacity) {
        return -1;
    }
    memcpy(out, formatted, (size_t)written + 1);
    return 0;
}
