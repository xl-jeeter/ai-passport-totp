#include "totp_ap_proto.h"

#include <stdio.h>
#include <string.h>

uint32_t totp_crc32(const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= bytes[i];
        for (int bit = 0; bit < 8; bit++) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

void totp_ap_format_ssid(char *out, size_t out_len, const uint8_t mac[6])
{
    if (out == NULL || out_len == 0 || mac == NULL) {
        return;
    }
    snprintf(out, out_len, "TOTP-%02X%02X", mac[4], mac[5]);
}

void totp_ap_format_password(char out[9], const uint8_t mac[6])
{
    if (out == NULL || mac == NULL) {
        return;
    }
    /* 盐 + 整机 MAC（6 字节）一次性 CRC32，取模 1e8 补零到 8 位数字。 */
    static const char salt[] = "totp-ap-v1";
    uint8_t buffer[sizeof(salt) - 1 + 6];
    memcpy(buffer, salt, sizeof(salt) - 1);
    memcpy(buffer + sizeof(salt) - 1, mac, 6);
    uint32_t crc = totp_crc32(buffer, sizeof(buffer));
    snprintf(out, 9, "%08lu", (unsigned long)(crc % 100000000u));
}

/* 常见系统/浏览器 Captive Portal 探测路径。 */
static const char *const k_captive_paths[] = {
    "/generate_204",           /* Android / ChromeOS */
    "/gen_204",                /* Android 旧版 */
    "/hotspot-detect.html",    /* iOS / macOS */
    "/library/test/success.html", /* iOS 旧版 */
    "/ncsi.txt",               /* Windows */
    "/connecttest.txt",        /* Windows 新版 */
    "/success.txt",            /* Firefox 旧版 */
    "/canonical.html",         /* Firefox */
    "/redirect",               /* 部分厂商探测 */
};

bool totp_captive_path(const char *uri)
{
    if (uri == NULL || uri[0] != '/') {
        return false;
    }
    size_t path_len = strcspn(uri, "?");
    for (size_t i = 0; i < sizeof(k_captive_paths) / sizeof(k_captive_paths[0]); i++) {
        const char *path = k_captive_paths[i];
        if (strlen(path) == path_len && memcmp(uri, path, path_len) == 0) {
            return true;
        }
    }
    return false;
}

size_t totp_dns_build_reply(const uint8_t *query, size_t query_len,
                            const uint8_t ip[4], uint8_t *out, size_t out_cap)
{
    if (query == NULL || ip == NULL || out == NULL || query_len < 12) {
        return 0;
    }
    if (((query[4] << 8) | query[5]) != 1) { /* 只处理 QDCOUNT=1 */
        return 0;
    }

    /* 问题段：QNAME（标签序列，不支持压缩指针）+ QTYPE + QCLASS */
    size_t pos = 12;
    for (;;) {
        if (pos >= query_len) {
            return 0;
        }
        uint8_t label = query[pos];
        if ((label & 0xC0u) != 0) {
            return 0;
        }
        pos++;
        if (label == 0) {
            break;
        }
        pos += label;
    }
    if (pos + 4 > query_len) {
        return 0;
    }
    uint16_t qtype = (uint16_t)((query[pos] << 8) | query[pos + 1]);
    uint16_t qclass = (uint16_t)((query[pos + 2] << 8) | query[pos + 3]);
    pos += 4;
    if (qclass != 1) { /* 只处理 IN 类 */
        return 0;
    }

    bool answer_a = (qtype == 1 || qtype == 255); /* A 或 ANY 才给地址 */
    size_t answer_len = answer_a ? 16 : 0;
    if (out_cap < pos + answer_len) {
        return 0;
    }

    memcpy(out, query, pos); /* 头 + 问题原样回显（查询尾部的 EDNS 等附加段丢弃） */
    out[2] = (uint8_t)(0x80u | 0x04u | (query[2] & 0x01u)); /* QR + AA，回显 RD */
    out[3] = 0;
    out[6] = 0;
    out[7] = answer_a ? 1 : 0; /* ANCOUNT */
    out[8] = out[9] = out[10] = out[11] = 0; /* NSCOUNT/ARCOUNT */

    if (answer_a) {
        uint8_t *answer = out + pos;
        answer[0] = 0xC0;
        answer[1] = 0x0C; /* 指向问题段里的 QNAME */
        answer[2] = 0x00;
        answer[3] = 0x01; /* TYPE A */
        answer[4] = 0x00;
        answer[5] = 0x01; /* CLASS IN */
        answer[6] = 0x00;
        answer[7] = 0x00;
        answer[8] = 0x00;
        answer[9] = 60;   /* TTL 60 秒 */
        answer[10] = 0x00;
        answer[11] = 0x04; /* RDLENGTH */
        memcpy(answer + 12, ip, 4);
    }
    return pos + answer_len;
}
