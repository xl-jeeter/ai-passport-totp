#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* SoftAP 配网纯逻辑：SSID/密码派生、Captive Portal 路径表、DNS 应答构造。
 * 不依赖 ESP-IDF/LVGL，可在 host 上编译并单测（tests/test_totp_ap_proto.c）。 */

/* IEEE 802.3 CRC32（多项式 0xEDB88320，初值/末值 0xFFFFFFFF）。
 * 暴露出来便于用标准校验值对拍（"123456789" → 0xCBF43926）。 */
uint32_t totp_crc32(const void *data, size_t len);

/* AP SSID："TOTP-XXXX"，XXXX = MAC 后 2 字节大写十六进制（例：TOTP-79D4）。
 * out_len 至少 10 字节。 */
void totp_ap_format_ssid(char *out, size_t out_len, const uint8_t mac[6]);

/* AP 密码：由 MAC 确定性派生的 8 位数字字符串，out 缓冲含结尾 NUL 共 9 字节。
 * 售后可凭 MAC 复算，屏幕可直接显示；注意 SSID 已暴露 MAC 后 2 字节，
 * WPA2 8 位数字本身也防不住离线爆破，此设计换取可复现而非高强度。 */
void totp_ap_format_password(char out[9], const uint8_t mac[6]);

/* Captive Portal 探测路径表。uri 可带查询串（按 '?' 截断后比较）。
 * 命中返回 true：HTTP 侧应 302 到配置页，配合 DNS 全应答实现手机自动弹页。 */
bool totp_captive_path(const char *uri);

/* DNS 应答构造：任何 A/ANY 查询都应答 ip（4 字节网络序）；其他类型应答空
 * NOERROR 让客户端回退到 A 记录。只支持 QDCOUNT=1、无压缩指针的查询。
 * 成功返回应答长度；查询非法或 out_cap 不足返回 0。 */
size_t totp_dns_build_reply(const uint8_t *query, size_t query_len,
                            const uint8_t ip[4], uint8_t *out, size_t out_cap);
