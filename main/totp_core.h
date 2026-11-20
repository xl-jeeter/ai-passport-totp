#pragma once

#include <stddef.h>
#include <stdint.h>

/* 解码 RFC 4648 Base32（大小写不敏感，忽略空格与 '='）。成功返回 0。 */
int base32_decode(const char *encoded, uint8_t *out, size_t out_capacity, size_t *out_len);

/* 计算 TOTP 码（RFC 6238）。
 * secret/secret_len: 已解码的原始密钥
 * digits: 6..8
 * algo: 0=SHA1, 1=SHA256, 2=SHA512
 * 返回 0 表示成功，code 写入 out（十进制字符串，补零到 digits 位）。 */
int totp_code(const uint8_t *secret, size_t secret_len, uint64_t counter,
              int digits, int algo, char *out, size_t out_capacity);

/* 计算当前时刻应使用的 TOTP 计数器。 */
uint64_t totp_counter(uint64_t unix_time, uint32_t period);

/* 还剩余多少秒进入下一个周期（1..period）。 */
uint32_t totp_remaining(uint64_t unix_time, uint32_t period);
