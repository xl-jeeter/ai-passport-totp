// HTTP 后台 REST 纯逻辑的 host 测试:URI 下标解析、算法名互转、账号字段校验。
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "totp_http_proto.h"

int main(void)
{
    // --- URI 下标解析 ---
    assert(totp_proto_account_index("/api/accounts/0", 3) == 0);
    assert(totp_proto_account_index("/api/accounts/2", 3) == 2);
    assert(totp_proto_account_index("/api/accounts/3", 3) == -1);   // 越界
    assert(totp_proto_account_index("/api/accounts/12", 3) == -1);  // 多位数越界
    assert(totp_proto_account_index("/api/accounts/", 3) == -1);    // 空下标
    assert(totp_proto_account_index("/api/accounts", 3) == -1);     // 无下标
    assert(totp_proto_account_index("/api/accounts/x", 3) == -1);   // 非数字
    assert(totp_proto_account_index("/api/accounts/1x", 3) == -1);  // 后缀垃圾
    assert(totp_proto_account_index("/api/accounts/1?x=2", 3) == 1); // 查询串不影响下标
    assert(totp_proto_account_index(NULL, 3) == -1);
    assert(totp_proto_account_index("/api/accounts/0", 0) == -1);   // 空列表

    // --- 算法名互转 ---
    assert(totp_proto_algo_from_name("SHA1") == 0);
    assert(totp_proto_algo_from_name("sha1") == 0);
    assert(totp_proto_algo_from_name("SHA256") == 1);
    assert(totp_proto_algo_from_name("sha512") == 2);
    assert(totp_proto_algo_from_name("") == 0);      // 空串走默认
    assert(totp_proto_algo_from_name(NULL) == 0);
    assert(totp_proto_algo_from_name("MD5") == -1);  // 未知
    assert(strcmp(totp_proto_algo_name(0), "SHA1") == 0);
    assert(strcmp(totp_proto_algo_name(1), "SHA256") == 0);
    assert(strcmp(totp_proto_algo_name(2), "SHA512") == 0);
    assert(strcmp(totp_proto_algo_name(9), "SHA1") == 0);

    // --- 字段校验与默认值 ---
    int d = -1, p = -1, a = -1;
    assert(totp_proto_account_fields("github", "JBSWY3DPEHPK3PXP", 0, 0, -1, &d, &p, &a));
    assert(d == 6 && p == 30 && a == 0);            // 全默认
    assert(totp_proto_account_fields("x", "JBSWY3DPEHPK3PXP", 8, 60, 2, &d, &p, &a));
    assert(d == 8 && p == 60 && a == 2);
    assert(!totp_proto_account_fields("", "JBSWY3DPEHPK3PXP", 6, 30, 0, NULL, NULL, NULL));  // 名字空
    assert(!totp_proto_account_fields("x", "", 6, 30, 0, NULL, NULL, NULL));                  // 密钥空
    assert(!totp_proto_account_fields(NULL, "JBSWY3DPEHPK3PXP", 6, 30, 0, NULL, NULL, NULL));
    assert(!totp_proto_account_fields("x", "JBSWY3DPEHPK3PXP", 5, 30, 0, NULL, NULL, NULL));  // 位数非法
    assert(!totp_proto_account_fields("x", "JBSWY3DPEHPK3PXP", 9, 30, 0, NULL, NULL, NULL));
    assert(!totp_proto_account_fields("x", "JBSWY3DPEHPK3PXP", 6, 5, 0, NULL, NULL, NULL));   // 周期非法
    assert(!totp_proto_account_fields("x", "JBSWY3DPEHPK3PXP", 6, 200, 0, NULL, NULL, NULL));
    assert(!totp_proto_account_fields("x", "JBSWY3DPEHPK3PXP", 6, 30, 3, NULL, NULL, NULL));  // 算法非法
    assert(!totp_proto_account_fields("x", "1!", 6, 30, 0, NULL, NULL, NULL));                // 非 Base32
    assert(!totp_proto_account_fields("x", "A", 6, 30, 0, NULL, NULL, NULL));                 // 解码后 0 字节

    printf("test_totp_http_proto: PASS\n");
    return 0;
}
