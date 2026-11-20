#pragma once

#include <stdbool.h>

/* HTTP 后台 REST 接口的纯逻辑（URI 下标解析、算法名互转、字段校验）。
 * 不依赖 ESP-IDF/LVGL，可在 host 上编译并单测（tests/test_totp_http_proto.c）。 */

/* 从形如 "/api/accounts/3" 的 URI 解析账号下标；count 为账号总数。
 * 成功返回 0..count-1；URI 非法、空下标或越界返回 -1。 */
int totp_proto_account_index(const char *uri, int count);

/* "SHA1"/"SHA256"/"SHA512"（大小写不敏感）→ 0/1/2；NULL 或空串 → 0（默认 SHA1）；
 * 未知名返回 -1。 */
int totp_proto_algo_from_name(const char *name);

/* 0/1/2 → "SHA1"/"SHA256"/"SHA512"；其他值按 0 处理。 */
const char *totp_proto_algo_name(int algo);

/* 校验并归一化账号字段（名字/密钥长度上限由调用方另查）：
 * name/secret 必须非空，secret 必须是合法 Base32；
 * digits 传 0 表示默认 6，仅接受 6..8；
 * period 传 0 表示默认 30，仅接受 10..120；
 * algo 传 -1 表示默认 0，仅接受 0..2。
 * out_* 可为 NULL。全部合法返回 true 并写出归一化后的值。 */
bool totp_proto_account_fields(const char *name, const char *secret,
                               int digits, int period, int algo,
                               int *out_digits, int *out_period, int *out_algo);
