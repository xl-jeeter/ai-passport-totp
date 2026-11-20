#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

/* 开机联网入口：NVS 有 Wi-Fi 凭据则 STA 连接（20 秒内拿到 IP 进入正常模式，
 * 超时/连续失败切 SoftAP 配网模式）；没有凭据直接进 SoftAP 配网模式。 */
void totp_net_start(void);

/* 请求重新校时（OK 长按时调用）。已有 NTP 在跑时只是重新发起一次同步；
 * AP 模式且 STA 未连接时是空操作（不空跑 SNTP 重试）。 */
void totp_time_sync_request(void);

/* 时间是否已可信（做 TOTP 计算的必要条件）。 */
bool totp_time_ready(void);

/* 当前 STA IP 字符串；未联网时为空串（界面显示「未联网」）。 */
const char *totp_net_ip(void);

/* ---- SoftAP 配网 ---- */

/* 当前是否处于配网（SoftAP）模式。 */
bool totp_net_is_ap(void);

/* AP 热点名（"TOTP-XXXX"）、密码（8 位数字）、地址（"192.168.4.1"）。 */
const char *totp_net_ap_ssid(void);
const char *totp_net_ap_password(void);
const char *totp_net_ap_ip(void);

/* 立即切到 SoftAP 配网模式（可从 STA 模式运行时切换，可重复调用）。
 * 切换后 STA 自动连接与 SNTP 停止，DNS/HTTP 配网服务就绪。 */
void totp_net_ap_start(void);

/* 关闭配网热点、回到 STA 模式（配网试连成功后调用；STA 已有 IP 时保持连接）。 */
void totp_net_ap_stop(void);

/* 保存凭据并试连（最多 20 秒）：成功写 ip_out 并返回 ESP_OK；失败写
 * err_out（"密码错误"/"找不到网络"/"连接超时"…）并返回 ESP_FAIL，留在 AP 模式。
 * ip_out/err_out 可为 NULL；err_out 为空时按"连接超时"处理。 */
esp_err_t totp_net_sta_try(const char *ssid, const char *password,
                           char *ip_out, size_t ip_len,
                           char *err_out, size_t err_len);

/* Wi-Fi 扫描结果（按信号从强到弱，同名 SSID 只留最强）。 */
typedef struct {
    char ssid[33];
    int rssi;
    char auth[12];
} totp_wifi_scan_item_t;

/* 扫描附近 Wi-Fi 并按信号降序填入 out（最多 max_items 条），返回条数；失败 -1。 */
int totp_net_wifi_scan(totp_wifi_scan_item_t *out, int max_items);
