#include "totp_net.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_sntp.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "totp_ap_proto.h"
#include "totp_dns.h"
#include "totp_http.h"
#include "totp_store.h"

static const char *TAG = "totp-net";

#define BOOT_CONNECT_TIMEOUT_MS 20000
#define STA_TRY_TIMEOUT_MS 20000
#define RECONNECT_DELAY_MS 3000

#define WORK_GOT_IP BIT0
#define WORK_AP_START BIT1

#define EV_GOT_IP BIT0
#define EV_STA_DOWN BIT1

static bool s_started;
static bool s_sntp_started;
static bool s_ap_active;  /* SoftAP 已开启（Wi-Fi 模式为 APSTA） */
static bool s_sta_auto;   /* STA 允许自动连接/重连（正常 STA 模式或开机试连） */
static bool s_trying;     /* 一次显式 STA 试连进行中（配网页保存 Wi-Fi） */
static bool s_sta_connected;
static int s_disconnect_reason;
static char s_ip[16];
static char s_ap_ssid[16];
static char s_ap_pass[9];
static char s_ap_ip[16] = "192.168.4.1";

static EventGroupHandle_t s_events;
static SemaphoreHandle_t s_op_lock; /* 串行化模式切换与试连的启动段 */
static esp_timer_handle_t s_reconnect_timer;
static esp_timer_handle_t s_boot_timer;
static EventGroupHandle_t s_work_bits;

static void on_reconnect_timer(void *arg)
{
    (void)arg;
    if (s_sta_auto && !s_trying && !s_sta_connected) {
        ESP_LOGI(TAG, "重连 Wi-Fi");
        esp_wifi_connect();
    }
}

static void on_boot_timeout(void *arg)
{
    (void)arg;
    if (!s_sta_connected) {
        ESP_LOGW(TAG, "开机 %d 秒未连上 Wi-Fi，切配网模式", BOOT_CONNECT_TIMEOUT_MS / 1000);
        if (s_work_bits != NULL) {
            xEventGroupSetBits(s_work_bits, WORK_AP_START);
        }
    }
}


/* 事件回调运行在 sys_evt 任务上（栈 2304B），里面做 printf/启动 HTTP/SNTP 会直接栈溢出。
 * 所有重活都投递到这个独立任务里执行。 */
static void net_worker_task(void *arg)
{
    (void)arg;
    for (;;) {
        EventBits_t bits = xEventGroupWaitBits(s_work_bits, WORK_GOT_IP | WORK_AP_START, pdTRUE,
                                               pdFALSE, portMAX_DELAY);
        if (bits & WORK_GOT_IP) {
            totp_http_start();
            totp_time_sync_request();
        }
        if (bits & WORK_AP_START) {
            totp_net_ap_start();
        }
    }
}

static void on_wifi_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        if (s_sta_auto || s_trying) {
            esp_wifi_connect();
        }
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *event = (wifi_event_sta_disconnected_t *)data;
        s_disconnect_reason = event != NULL ? event->reason : 0;
        s_sta_connected = false;
        s_ip[0] = '\0';
        if (s_trying) {
            /* 试连由 totp_net_sta_try 收口：报事件给等待方决定重试或放弃 */
            xEventGroupSetBits(s_events, EV_STA_DOWN);
        } else if (s_sta_auto) {
            ESP_LOGW(TAG, "Wi-Fi 断开（原因 %d），%d 秒后重连", s_disconnect_reason,
                     RECONNECT_DELAY_MS / 1000);
            esp_timer_start_once(s_reconnect_timer, (uint64_t)RECONNECT_DELAY_MS * 1000);
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        snprintf(s_ip, sizeof(s_ip), IPSTR, IP2STR(&event->ip_info.ip));
        s_sta_connected = true;
        esp_timer_stop(s_reconnect_timer);
        esp_timer_stop(s_boot_timer);
        /* 不要在这里打日志：sys_evt 任务栈只有 2.3KB，vfprintf 会直接栈溢出。 */
        if (s_work_bits != NULL) {
            xEventGroupSetBits(s_work_bits, WORK_GOT_IP);
        }
        if (s_trying) {
            xEventGroupSetBits(s_events, EV_GOT_IP);
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_LOST_IP) {
        s_ip[0] = '\0';
        s_sta_connected = false;
    }
}

static void on_time_synced(struct timeval *tv)
{
    ESP_LOGI(TAG, "NTP 校时完成：%lld", (long long)tv->tv_sec);
}

/* 幂等初始化：网络、事件循环、Wi-Fi 驱动、AP/STA 网卡、定时器、热点参数。 */
static void net_init(void)
{
    if (s_started) {
        return;
    }
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    esp_netif_create_default_wifi_ap();

    s_events = xEventGroupCreate();
    s_work_bits = xEventGroupCreate();
    xTaskCreate(net_worker_task, "totp-net-work", 5120, NULL, 4, NULL);
    s_op_lock = xSemaphoreCreateMutex();
    esp_timer_create_args_t timer_args = {.callback = on_reconnect_timer, .name = "totp-reconnect"};
    ESP_ERROR_CHECK(esp_timer_create(&timer_args, &s_reconnect_timer));
    timer_args.callback = on_boot_timeout;
    timer_args.name = "totp-boot";
    ESP_ERROR_CHECK(esp_timer_create(&timer_args, &s_boot_timer));

    wifi_init_config_t config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&config));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_wifi_event,
                                                        NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, ESP_EVENT_ANY_ID, on_wifi_event,
                                                        NULL, NULL));

    /* 热点名/密码从整机 MAC 确定性派生（售后可复算），开机即可显示 */
    uint8_t mac[6];
    ESP_ERROR_CHECK(esp_read_mac(mac, ESP_MAC_WIFI_STA));
    totp_ap_format_ssid(s_ap_ssid, sizeof(s_ap_ssid), mac);
    totp_ap_format_password(s_ap_pass, mac);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    s_started = true;
}

void totp_net_start(void)
{
    if (s_started) {
        return;
    }
    net_init();
    char ssid[33] = {0};
    char password[65] = {0};
    if (store_get_wifi(ssid, sizeof(ssid), password, sizeof(password)) != ESP_OK || ssid[0] == '\0') {
        ESP_LOGI(TAG, "没有保存 Wi-Fi，进入配网模式（手机连热点 %s 配置）", s_ap_ssid);
        totp_net_ap_start();
        return;
    }

    wifi_config_t wifi_config = {0};
    size_t ssid_len = strnlen(ssid, sizeof(wifi_config.sta.ssid));
    memcpy(wifi_config.sta.ssid, ssid, ssid_len);
    size_t password_len = strnlen(password, sizeof(wifi_config.sta.password));
    memcpy(wifi_config.sta.password, password, password_len);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    s_sta_auto = true;
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    esp_wifi_connect();
    esp_timer_start_once(s_boot_timer, (uint64_t)BOOT_CONNECT_TIMEOUT_MS * 1000);
    ESP_LOGI(TAG, "开始连接 Wi-Fi: %s（%d 秒内未连上则进配网模式）", ssid,
             BOOT_CONNECT_TIMEOUT_MS / 1000);
}

void totp_net_ap_start(void)
{
    net_init();
    xSemaphoreTake(s_op_lock, portMAX_DELAY);
    if (s_ap_active) {
        xSemaphoreGive(s_op_lock);
        return;
    }

    /* 停掉 STA 自动连接与 SNTP：AP 模式下没有 STA 连接时不空跑重试 */
    s_sta_auto = false;
    s_trying = false;
    esp_timer_stop(s_reconnect_timer);
    esp_timer_stop(s_boot_timer);
    esp_wifi_disconnect();
    if (s_sntp_started) {
        esp_sntp_stop();
        s_sntp_started = false;
    }
    s_sta_connected = false;
    s_ip[0] = '\0';

    wifi_config_t ap_config = {0};
    snprintf((char *)ap_config.ap.ssid, sizeof(ap_config.ap.ssid), "%s", s_ap_ssid);
    ap_config.ap.ssid_len = (uint8_t)strlen(s_ap_ssid);
    snprintf((char *)ap_config.ap.password, sizeof(ap_config.ap.password), "%s", s_ap_pass);
    ap_config.ap.channel = 6;
    ap_config.ap.max_connection = 4;
    ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA)); /* 保留 STA 口，配网页保存后直接试连 */
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    s_ap_active = true;

    /* 热点地址按网卡实际配置取（默认 192.168.4.1），DNS 全应答指向它 */
    uint8_t ip_bytes[4] = {192, 168, 4, 1};
    esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (ap_netif != NULL) {
        esp_netif_ip_info_t info;
        if (esp_netif_get_ip_info(ap_netif, &info) == ESP_OK) {
            ip_bytes[0] = esp_ip4_addr1(&info.ip);
            ip_bytes[1] = esp_ip4_addr2(&info.ip);
            ip_bytes[2] = esp_ip4_addr3(&info.ip);
            ip_bytes[3] = esp_ip4_addr4(&info.ip);
            snprintf(s_ap_ip, sizeof(s_ap_ip), IPSTR, IP2STR(&info.ip));
        }
    }
    totp_dns_start(ip_bytes);
    totp_http_start();
    ESP_LOGI(TAG, "配网模式: 热点 %s，密码 %s，网址 %s", s_ap_ssid, s_ap_pass, s_ap_ip);
    xSemaphoreGive(s_op_lock);
}

void totp_net_ap_stop(void)
{
    if (!s_started) {
        return;
    }
    xSemaphoreTake(s_op_lock, portMAX_DELAY);
    if (!s_ap_active) {
        xSemaphoreGive(s_op_lock);
        return;
    }
    s_ap_active = false;
    totp_dns_stop();
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    s_sta_auto = true;
    ESP_LOGI(TAG, "配网热点已关闭，回到 STA 模式（%s）", s_ip);
    xSemaphoreGive(s_op_lock);
}

/* 断开原因 → 是否立即判负 + 提示语。密码错误类快速失败，避免干等 20 秒。 */
static bool try_failure_message(int reason, const char **message)
{
    switch (reason) {
    case WIFI_REASON_AUTH_FAIL:
    case WIFI_REASON_HANDSHAKE_TIMEOUT:
    case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
    case WIFI_REASON_GROUP_KEY_UPDATE_TIMEOUT:
        *message = "密码错误";
        return true;
    case WIFI_REASON_NO_AP_FOUND:
    case WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD:
    case WIFI_REASON_NO_AP_FOUND_IN_RSSI_THRESHOLD:
    case WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY:
        *message = "找不到网络";
        return true;
    case WIFI_REASON_ASSOC_FAIL:
        *message = "无法加入网络";
        return true;
    default:
        return false;
    }
}

esp_err_t totp_net_sta_try(const char *ssid, const char *password,
                           char *ip_out, size_t ip_len,
                           char *err_out, size_t err_len)
{
    if (err_out != NULL && err_len > 0) {
        err_out[0] = '\0';
    }
    if (!s_started || ssid == NULL || ssid[0] == '\0') {
        if (err_out != NULL && err_len > 0) {
            snprintf(err_out, err_len, "参数错误");
        }
        return ESP_ERR_INVALID_ARG;
    }
    if (password == NULL) {
        password = "";
    }
    if (store_set_wifi(ssid, password) != ESP_OK) {
        if (err_out != NULL && err_len > 0) {
            snprintf(err_out, err_len, "保存失败");
        }
        return ESP_FAIL;
    }

    xSemaphoreTake(s_op_lock, portMAX_DELAY);
    if (s_trying) {
        xSemaphoreGive(s_op_lock);
        if (err_out != NULL && err_len > 0) {
            snprintf(err_out, err_len, "正在连接中");
        }
        return ESP_ERR_INVALID_STATE;
    }
    s_trying = true;
    xEventGroupClearBits(s_events, EV_GOT_IP | EV_STA_DOWN);

    wifi_config_t sta_config = {0};
    size_t ssid_len = strnlen(ssid, sizeof(sta_config.sta.ssid));
    memcpy(sta_config.sta.ssid, ssid, ssid_len);
    size_t password_len = strnlen(password, sizeof(sta_config.sta.password));
    memcpy(sta_config.sta.password, password, password_len);
    sta_config.sta.threshold.authmode = WIFI_AUTH_OPEN; /* 开放网络也可配 */
    esp_timer_stop(s_reconnect_timer);
    esp_timer_stop(s_boot_timer);
    ESP_ERROR_CHECK(esp_wifi_set_mode(s_ap_active ? WIFI_MODE_APSTA : WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_config));
    esp_wifi_disconnect(); /* 换网先断开（未连接时返回错误，无妨） */
    esp_wifi_connect();
    xSemaphoreGive(s_op_lock); /* 等待段不持锁，避免堵住其他模式切换 */

    const char *failure = "连接超时";
    bool ok = false;
    TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(STA_TRY_TIMEOUT_MS);
    for (;;) {
        TickType_t now = xTaskGetTickCount();
        TickType_t remaining = (TickType_t)(deadline - now);
        if ((int32_t)remaining <= 0) {
            break;
        }
        EventBits_t bits = xEventGroupWaitBits(s_events, EV_GOT_IP | EV_STA_DOWN, pdTRUE,
                                               pdFALSE, remaining);
        if (bits & EV_GOT_IP) {
            ok = true;
            break;
        }
        if (bits & EV_STA_DOWN) {
            const char *message = NULL;
            if (try_failure_message(s_disconnect_reason, &message)) {
                failure = message;
                break;
            }
            esp_wifi_connect(); /* 瞬时断开：继续试到超时为止 */
        }
    }
    s_trying = false;

    if (ok) {
        if (ip_out != NULL && ip_len > 0) {
            snprintf(ip_out, ip_len, "%s", s_ip);
        }
        ESP_LOGI(TAG, "配网试连成功：%s（%s）", ssid, s_ip);
        return ESP_OK;
    }
    esp_wifi_disconnect();
    if (err_out != NULL && err_len > 0) {
        snprintf(err_out, err_len, "%s", failure);
    }
    ESP_LOGW(TAG, "配网试连失败：%s（%s）", ssid, failure);
    return ESP_FAIL;
}

static const char *auth_name(wifi_auth_mode_t mode)
{
    switch (mode) {
    case WIFI_AUTH_OPEN:
        return "OPEN";
    case WIFI_AUTH_WEP:
        return "WEP";
    case WIFI_AUTH_WPA_PSK:
        return "WPA";
    case WIFI_AUTH_WPA2_PSK:
        return "WPA2";
    case WIFI_AUTH_WPA_WPA2_PSK:
        return "WPA/2";
    case WIFI_AUTH_WPA2_ENTERPRISE:
        return "WPA2-EAP";
    case WIFI_AUTH_WPA3_PSK:
        return "WPA3";
    case WIFI_AUTH_WPA2_WPA3_PSK:
        return "WPA2/3";
    case WIFI_AUTH_WAPI_PSK:
        return "WAPI";
    case WIFI_AUTH_OWE:
        return "OWE";
    default:
        return "?";
    }
}

int totp_net_wifi_scan(totp_wifi_scan_item_t *out, int max_items)
{
    if (!s_started || out == NULL || max_items <= 0) {
        return -1;
    }
    wifi_scan_config_t config = {0};
    config.show_hidden = false;
    if (esp_wifi_scan_start(&config, true) != ESP_OK) {
        return -1;
    }
    static wifi_ap_record_t records[16]; /* 仅 httpd 任务调用，静态缓冲省栈 */
    uint16_t ap_num = (uint16_t)(sizeof(records) / sizeof(records[0]));
    if (esp_wifi_scan_get_ap_records(&ap_num, records) != ESP_OK) {
        return -1;
    }

    int count = 0;
    for (uint16_t i = 0; i < ap_num; i++) {
        if (records[i].ssid[0] == '\0') {
            continue;
        }
        int duplicate = -1;
        for (int j = 0; j < count; j++) {
            if (strcmp(out[j].ssid, (const char *)records[i].ssid) == 0) {
                duplicate = j;
                break;
            }
        }
        if (duplicate >= 0) {
            if (records[i].rssi > out[duplicate].rssi) { /* 同名保留最强 */
                out[duplicate].rssi = records[i].rssi;
                snprintf(out[duplicate].auth, sizeof(out[duplicate].auth), "%s",
                         auth_name(records[i].authmode));
            }
            continue;
        }
        int slot;
        if (count < max_items) {
            slot = count++;
        } else {
            int weakest = 0;
            for (int j = 1; j < count; j++) {
                if (out[j].rssi < out[weakest].rssi) {
                    weakest = j;
                }
            }
            if (records[i].rssi <= out[weakest].rssi) {
                continue;
            }
            slot = weakest;
        }
        snprintf(out[slot].ssid, sizeof(out[slot].ssid), "%s", (const char *)records[i].ssid);
        out[slot].rssi = records[i].rssi;
        snprintf(out[slot].auth, sizeof(out[slot].auth), "%s", auth_name(records[i].authmode));
    }

    for (int i = 1; i < count; i++) { /* 按信号降序插入排序 */
        totp_wifi_scan_item_t key = out[i];
        int j = i - 1;
        while (j >= 0 && out[j].rssi < key.rssi) {
            out[j + 1] = out[j];
            j--;
        }
        out[j + 1] = key;
    }
    return count;
}

void totp_time_sync_request(void)
{
    if (!s_started || !s_sta_connected) {
        return; /* AP 模式且无 STA 连接：不做 SNTP 重试 */
    }
    if (!s_sntp_started) {
        esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
        esp_sntp_setservername(0, "ntp.aliyun.com");
        esp_sntp_setservername(1, "cn.pool.ntp.org");
        sntp_set_time_sync_notification_cb(on_time_synced);
        esp_sntp_init();
        s_sntp_started = true;
    } else {
        esp_sntp_restart();
    }
}

bool totp_time_ready(void)
{
    return time(NULL) > 1700000000;
}

const char *totp_net_ip(void)
{
    return s_ip;
}

bool totp_net_is_ap(void)
{
    return s_ap_active;
}

const char *totp_net_ap_ssid(void)
{
    return s_ap_ssid;
}

const char *totp_net_ap_password(void)
{
    return s_ap_pass;
}

const char *totp_net_ap_ip(void)
{
    return s_ap_ip;
}
