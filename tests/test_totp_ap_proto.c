// SoftAP 配网纯逻辑的 host 测试:CRC32 对拍、AP 密码派生、SSID 格式化、
// Captive Portal 路径表、DNS 应答构造。
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "totp_ap_proto.h"

/* 构造一条 QDCOUNT=1 的标准查询：ID 0x1234，RD，QNAME=<name>，QTYPE/QCLASS。 */
static size_t make_query(uint8_t *out, const uint8_t *qname, size_t qname_len,
                         uint16_t qtype, uint16_t qclass, int with_edns)
{
    size_t pos = 0;
    out[pos++] = 0x12;
    out[pos++] = 0x34; /* ID */
    out[pos++] = 0x01;
    out[pos++] = 0x00; /* 标准查询 + RD */
    out[pos++] = 0x00;
    out[pos++] = 0x01; /* QDCOUNT=1 */
    out[pos++] = 0x00;
    out[pos++] = 0x00;
    out[pos++] = 0x00;
    out[pos++] = 0x00;
    out[pos++] = 0x00;
    out[pos++] = with_edns ? 0x01 : 0x00; /* ARCOUNT */
    memcpy(out + pos, qname, qname_len);
    pos += qname_len;
    out[pos++] = (uint8_t)(qtype >> 8);
    out[pos++] = (uint8_t)qtype;
    out[pos++] = (uint8_t)(qclass >> 8);
    out[pos++] = (uint8_t)qclass;
    if (with_edns) { /* EDNS OPT 附加记录：DNS 查询里常见，应答应丢弃它 */
        static const uint8_t opt[] = {
            0x00,                   /* NAME: 根 */
            0x00, 0x29,             /* TYPE OPT (41) */
            0x10, 0x00,             /* CLASS = 4096 UDP payload size */
            0x00, 0x00, 0x00, 0x00, /* TTL */
            0x00, 0x00,             /* RDLENGTH=0 */
        };
        memcpy(out + pos, opt, sizeof(opt));
        pos += sizeof(opt);
    }
    return pos;
}

int main(void)
{
    // --- CRC32:IEEE 802.3 标准校验值，保证派生可跨实现复算 ---
    assert(totp_crc32("123456789", 9) == 0xCBF43926u);
    assert(totp_crc32("", 0) == 0x00000000u);

    // --- AP 密码派生:确定性、8 位数字、黄金值锁定（售后按 MAC 复算） ---
    const uint8_t mac0[6] = {0x11, 0x22, 0x33, 0x44, 0x79, 0xD4};
    const uint8_t mac1[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const uint8_t mac2[6] = {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA};
    char pass[9];
    totp_ap_format_password(pass, mac0);
    assert(strcmp(pass, "18651239") == 0);
    totp_ap_format_password(pass, mac1);
    assert(strcmp(pass, "16304668") == 0);
    totp_ap_format_password(pass, mac2);
    assert(strcmp(pass, "89263243") == 0);
    // 重复调用结果一致;全为数字且恰好 8 位
    totp_ap_format_password(pass, mac0);
    char pass_again[9];
    totp_ap_format_password(pass_again, mac0);
    assert(strcmp(pass, pass_again) == 0);
    assert(strlen(pass) == 8);
    for (int i = 0; i < 8; i++) {
        assert(pass[i] >= '0' && pass[i] <= '9');
    }
    // 后 2 字节相同的 MAC 密码仍应不同(熵取自整机 MAC,不只 SSID 暴露的 2 字节)
    const uint8_t mac3[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0x79, 0xD4};
    char pass3[9];
    totp_ap_format_password(pass3, mac3);
    assert(strcmp(pass3, "18651239") != 0);

    // --- SSID 格式化:TOTP-XXXX,XXXX 为 MAC 后 2 字节大写十六进制 ---
    char ssid[16];
    totp_ap_format_ssid(ssid, sizeof(ssid), mac0);
    assert(strcmp(ssid, "TOTP-79D4") == 0);
    totp_ap_format_ssid(ssid, sizeof(ssid), mac1);
    assert(strcmp(ssid, "TOTP-0000") == 0);
    totp_ap_format_ssid(ssid, sizeof(ssid), mac2);
    assert(strcmp(ssid, "TOTP-BBAA") == 0);
    assert(strlen(ssid) == 9);

    // --- Captive Portal 路径表 ---
    assert(totp_captive_path("/generate_204"));
    assert(totp_captive_path("/gen_204"));
    assert(totp_captive_path("/hotspot-detect.html"));
    assert(totp_captive_path("/library/test/success.html"));
    assert(totp_captive_path("/ncsi.txt"));
    assert(totp_captive_path("/connecttest.txt"));
    assert(totp_captive_path("/success.txt"));
    assert(totp_captive_path("/canonical.html"));
    assert(totp_captive_path("/redirect"));
    assert(totp_captive_path("/generate_204?x=1"));   // 查询串不影响命中
    assert(!totp_captive_path("/generate_20"));       // 前缀不算
    assert(!totp_captive_path("/generate_2044"));
    assert(!totp_captive_path("/"));                  // 配置页本身
    assert(!totp_captive_path("/api/status"));
    assert(!totp_captive_path("/Generate_204"));      // 大小写敏感
    assert(!totp_captive_path("generate_204"));       // 必须绝对路径
    assert(!totp_captive_path(NULL));

    // --- DNS 应答构造 ---
    const uint8_t ip[4] = {192, 168, 4, 1};
    uint8_t qname_a[] = {1, 'a', 2, 'c', 'n', 0}; // "a.cn"
    uint8_t query[128];
    uint8_t reply[256];

    // A 查询 → 16 字节应答记录
    size_t qlen = make_query(query, qname_a, sizeof(qname_a), 1, 1, 0);
    size_t rlen = totp_dns_build_reply(query, qlen, ip, reply, sizeof(reply));
    assert(rlen == qlen + 16);
    assert(reply[0] == 0x12 && reply[1] == 0x34);           // ID 回显
    assert(reply[2] == 0x85 && reply[3] == 0x00);           // QR|AA + 回显 RD
    assert(reply[4] == 0x00 && reply[5] == 0x01);           // QDCOUNT=1
    assert(reply[6] == 0x00 && reply[7] == 0x01);           // ANCOUNT=1
    assert(reply[8] == 0x00 && reply[9] == 0x00 &&
           reply[10] == 0x00 && reply[11] == 0x00);         // 无授权/附加段
    assert(memcmp(reply + 12, query + 12, qlen - 12) == 0); // 问题段回显
    const uint8_t *answer = reply + qlen;
    assert(answer[0] == 0xC0 && answer[1] == 0x0C); // QNAME 指针
    assert(answer[2] == 0x00 && answer[3] == 0x01); // TYPE A
    assert(answer[4] == 0x00 && answer[5] == 0x01); // CLASS IN
    assert(answer[8] == 0x00 && answer[9] == 60);   // TTL 60
    assert(answer[10] == 0x00 && answer[11] == 0x04);
    assert(memcmp(answer + 12, ip, 4) == 0);

    // 带 EDNS 附加段的查询:应答丢弃附加段,ARCOUNT 归零
    qlen = make_query(query, qname_a, sizeof(qname_a), 1, 1, 1);
    rlen = totp_dns_build_reply(query, qlen, ip, reply, sizeof(reply));
    assert(qlen == 12 + sizeof(qname_a) + 4 + 11);           // 头 + 问题 + OPT
    assert(rlen == 12 + sizeof(qname_a) + 4 + 16);           // 问题 + 应答,OPT 被丢弃
    assert(reply[10] == 0x00 && reply[11] == 0x00);

    // ANY(255) 查询也给地址
    qlen = make_query(query, qname_a, sizeof(qname_a), 255, 1, 0);
    rlen = totp_dns_build_reply(query, qlen, ip, reply, sizeof(reply));
    assert(rlen == qlen + 16 && reply[7] == 0x01);

    // AAAA/其他类型:空 NOERROR,让客户端回退到 A
    qlen = make_query(query, qname_a, sizeof(qname_a), 28, 1, 0);
    rlen = totp_dns_build_reply(query, qlen, ip, reply, sizeof(reply));
    assert(rlen == qlen && reply[7] == 0x00 && (reply[2] & 0x80) != 0);

    // 非 IN 类:拒绝
    qlen = make_query(query, qname_a, sizeof(qname_a), 1, 3, 0);
    assert(totp_dns_build_reply(query, qlen, ip, reply, sizeof(reply)) == 0);

    // QDCOUNT=2:拒绝
    qlen = make_query(query, qname_a, sizeof(qname_a), 1, 1, 0);
    query[5] = 2;
    assert(totp_dns_build_reply(query, qlen, ip, reply, sizeof(reply)) == 0);

    // QNAME 带压缩指针:拒绝
    qlen = make_query(query, qname_a, sizeof(qname_a), 1, 1, 0);
    query[12] = 0xC0;
    assert(totp_dns_build_reply(query, qlen, ip, reply, sizeof(reply)) == 0);

    // 截断的查询/输出缓冲:拒绝
    qlen = make_query(query, qname_a, sizeof(qname_a), 1, 1, 0);
    assert(totp_dns_build_reply(query, qlen - 1, ip, reply, sizeof(reply)) == 0); // QCLASS 被截断
    assert(totp_dns_build_reply(query, 5, ip, reply, sizeof(reply)) == 0);
    assert(totp_dns_build_reply(query, qlen, ip, reply, qlen) == 0); // 容不下应答
    assert(totp_dns_build_reply(NULL, qlen, ip, reply, sizeof(reply)) == 0);

    printf("test_totp_ap_proto: PASS\n");
    return 0;
}
