#include "totp_dns.h"

#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "totp_ap_proto.h"

static const char *TAG = "totp-dns";

#define DNS_PORT 53
#define DNS_QUERY_MAX 512
#define DNS_REPLY_MAX (DNS_QUERY_MAX + 32)

static volatile bool s_running;
static volatile bool s_stop;
static uint8_t s_ip[4];

static void dns_task(void *arg)
{
    (void)arg;
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd < 0) {
        ESP_LOGE(TAG, "DNS socket 创建失败");
        s_running = false;
        vTaskDelete(NULL);
        return;
    }
    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    /* 500 ms 接收超时：轮询停止标志，避免 stop 时挂死在 recvfrom 上 */
    struct timeval timeout = {.tv_sec = 0, .tv_usec = 500000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        ESP_LOGE(TAG, "DNS 端口 %d 绑定失败", DNS_PORT);
        close(fd);
        s_running = false;
        vTaskDelete(NULL);
        return;
    }

    /* 单任务独占，静态缓冲省栈（4 KB 栈任务里不放 1 KB 数组） */
    static uint8_t query_buf[DNS_QUERY_MAX];
    static uint8_t reply_buf[DNS_REPLY_MAX];
    ESP_LOGI(TAG, "DNS 服务已启动（UDP %d）", DNS_PORT);
    while (!s_stop) {
        struct sockaddr_in source;
        socklen_t source_len = sizeof(source);
        int received = recvfrom(fd, query_buf, sizeof(query_buf), 0,
                                (struct sockaddr *)&source, &source_len);
        if (received < 0) {
            continue; /* 超时或临时错误，回去检查停止标志 */
        }
        uint8_t ip[4];
        memcpy(ip, s_ip, sizeof(ip));
        size_t reply_len = totp_dns_build_reply(query_buf, (size_t)received, ip,
                                                reply_buf, sizeof(reply_buf));
        if (reply_len > 0) {
            sendto(fd, reply_buf, reply_len, 0, (struct sockaddr *)&source, source_len);
        }
    }
    close(fd);
    ESP_LOGI(TAG, "DNS 服务已停止");
    s_running = false;
    vTaskDelete(NULL);
}

void totp_dns_start(const uint8_t ip[4])
{
    if (ip == NULL) {
        return;
    }
    memcpy(s_ip, ip, sizeof(s_ip));
    if (s_running) {
        return;
    }
    s_stop = false;
    s_running = true;
    if (xTaskCreate(dns_task, "totp-dns", 4096, NULL, 3, NULL) != pdPASS) {
        s_running = false;
        ESP_LOGE(TAG, "DNS 任务创建失败");
    }
}

void totp_dns_stop(void)
{
    if (!s_running) {
        return;
    }
    s_stop = true;
    for (int i = 0; i < 20 && s_running; i++) { /* 最多等 1 秒（500 ms 超时粒度） */
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}
