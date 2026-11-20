#pragma once

#include <stdint.h>

/* Captive Portal 的最小 DNS 服务（UDP 53）：任何 A 查询都应答 AP 的 IP，
 * 让手机连上热点后自动弹出配置页。独立小任务，不阻塞 httpd。 */

/* 启动 DNS 服务任务（已运行则只更新应答 IP）。ip 为 4 字节网络序。 */
void totp_dns_start(const uint8_t ip[4]);

/* 停止 DNS 服务（阻塞等待任务退出，最多约 1 秒）。 */
void totp_dns_stop(void);
