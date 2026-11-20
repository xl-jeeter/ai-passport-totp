#include "totp_console.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "totp_app.h"
#include "totp_core.h"
#include "totp_net.h"
#include "totp_store.h"

static const char *TAG = "totp-console";

static void url_decode(char *text)
{
    char *write = text;
    for (char *read = text; *read != '\0'; read++) {
        if (*read == '%' && isxdigit((unsigned char)read[1]) && isxdigit((unsigned char)read[2])) {
            char hex[3] = {read[1], read[2], 0};
            *write++ = (char)strtol(hex, NULL, 16);
            read += 2;
        } else if (*read == '+') {
            *write++ = ' ';
        } else {
            *write++ = *read;
        }
    }
    *write = '\0';
}

static int algo_from_name(const char *name)
{
    if (name == NULL) {
        return 0;
    }
    if (strcasecmp(name, "SHA256") == 0) {
        return 1;
    }
    if (strcasecmp(name, "SHA512") == 0) {
        return 2;
    }
    return 0;
}

static const char *algo_name(int algo)
{
    switch (algo) {
    case 1:
        return "SHA256";
    case 2:
        return "SHA512";
    default:
        return "SHA1";
    }
}

static bool parse_otpauth(char *uri, totp_account_t *account)
{
    if (strncasecmp(uri, "otpauth://totp/", 15) != 0) {
        return false;
    }
    char *label = uri + 15;
    char *query = strchr(label, '?');
    if (query == NULL) {
        return false;
    }
    *query++ = '\0';
    url_decode(label);
    snprintf(account->name, sizeof(account->name), "%s", label[0] == '\0' ? "acct" : label);
    account->digits = 6;
    account->period = 30;
    account->algo = 0;

    char *save = NULL;
    for (char *param = strtok_r(query, "&", &save); param != NULL; param = strtok_r(NULL, "&", &save)) {
        char *eq = strchr(param, '=');
        if (eq == NULL) {
            continue;
        }
        *eq++ = '\0';
        url_decode(eq);
        if (strcasecmp(param, "secret") == 0) {
            snprintf(account->secret, sizeof(account->secret), "%s", eq);
        } else if (strcasecmp(param, "digits") == 0) {
            int value = atoi(eq);
            if (value >= 6 && value <= 8) {
                account->digits = (uint8_t)value;
            }
        } else if (strcasecmp(param, "period") == 0) {
            int value = atoi(eq);
            if (value >= 10 && value <= 120) {
                account->period = (uint16_t)value;
            }
        } else if (strcasecmp(param, "algorithm") == 0) {
            account->algo = (uint8_t)algo_from_name(eq);
        }
    }
    return account->secret[0] != '\0';
}

static void print_accounts(void)
{
    int total = store_count();
    if (total == 0) {
        printf("(空)\n");
        return;
    }
    time_t now = time(NULL);
    for (int i = 0; i < total; i++) {
        totp_account_t account;
        if (store_get(i, &account) != ESP_OK) {
            continue;
        }
        char code[16] = "------";
        uint8_t key[96];
        size_t key_len = 0;
        if (now > 1700000000 &&
            base32_decode(account.secret, key, sizeof(key), &key_len) == 0 && key_len > 0 &&
            totp_code(key, key_len, totp_counter((uint64_t)now, account.period), account.digits,
                      account.algo, code, sizeof(code)) == 0) {
            printf("[%d] %-18s %s (%02lu/%us) %s\n", i, account.name, code,
                   (unsigned long)(totp_remaining((uint64_t)now, account.period)),
                   (unsigned)account.period, algo_name(account.algo));
        } else {
            printf("[%d] %-18s (未授时或密钥无效)\n", i, account.name);
        }
    }
}

static void handle_line(char *line)
{
    char *argv[8] = {0};
    int argc = 0;
    char *save = NULL;
    for (char *token = strtok_r(line, " \t", &save); token != NULL && argc < 8;
         token = strtok_r(NULL, " \t", &save)) {
        argv[argc++] = token;
    }
    if (argc == 0) {
        return;
    }

    if (strcasecmp(argv[0], "help") == 0) {
        printf("命令: add/addurl/list/del/time/wifi/ap/wifi-clear/reboot\n"
               "  addurl otpauth://totp/<名字>?secret=<BASE32>&issuer=...\n"
               "  add <名字> <BASE32> [位数] [周期] [sha1|sha256|sha512]\n"
               "  list | del <名字|编号>\n"
               "  time [epoch]   查看/设置时间\n"
               "  wifi <SSID> <密码>   保存并重启（之后自动 NTP）\n"
               "  ap   立即开配网热点（打印热点名/密码/网址）\n"
               "  wifi-clear   清除已保存 Wi-Fi（下次开机进配网模式）\n");
    } else if (strcasecmp(argv[0], "list") == 0) {
        print_accounts();
    } else if (strcasecmp(argv[0], "addurl") == 0) {
        static char joined[512];
        joined[0] = '\0';
        for (int i = 1; i < argc; i++) {
            strncat(joined, argv[i], sizeof(joined) - strlen(joined) - 1);
        }
        totp_account_t account = {0};
        if (!parse_otpauth(joined, &account)) {
            printf("链接解析失败\n");
            return;
        }
        if (store_add(&account, NULL) == ESP_OK) {
            printf("已导入 %s\n", account.name);
        } else {
            printf("保存失败（上限 %d 个）\n", TOTP_MAX_ACCOUNTS);
        }
        totp_app_reload();
    } else if (strcasecmp(argv[0], "add") == 0) {
        if (argc < 3) {
            printf("用法: add <名字> <BASE32> [位数] [周期] [算法]\n");
            return;
        }
        totp_account_t account = {0};
        snprintf(account.name, sizeof(account.name), "%s", argv[1]);
        snprintf(account.secret, sizeof(account.secret), "%s", argv[2]);
        account.digits = argc > 3 ? (uint8_t)atoi(argv[3]) : 6;
        account.period = argc > 4 ? (uint16_t)atoi(argv[4]) : 30;
        account.algo = argc > 5 ? (uint8_t)algo_from_name(argv[5]) : 0;
        uint8_t key[96];
        size_t key_len = 0;
        if (base32_decode(account.secret, key, sizeof(key), &key_len) != 0 || key_len == 0) {
            printf("密钥不是合法 Base32\n");
            return;
        }
        if (store_add(&account, NULL) == ESP_OK) {
            printf("已添加 %s\n", account.name);
        } else {
            printf("保存失败（上限 %d 个）\n", TOTP_MAX_ACCOUNTS);
        }
        totp_app_reload();
    } else if (strcasecmp(argv[0], "del") == 0) {
        int index = 0;
        if (argc < 2 || store_find(argv[1], &index) != ESP_OK) {
            printf("找不到账号\n");
            return;
        }
        printf(store_delete(index) == ESP_OK ? "已删除\n" : "删除失败\n");
        totp_app_reload();
    } else if (strcasecmp(argv[0], "time") == 0) {
        if (argc > 1) {
            struct timeval tv = {.tv_sec = (time_t)strtoll(argv[1], NULL, 10), .tv_usec = 0};
            settimeofday(&tv, NULL);
            printf("时间已设置\n");
            totp_app_time_synced();
        }
        printf("当前: %lld\n", (long long)time(NULL));
    } else if (strcasecmp(argv[0], "wifi") == 0) {
        if (argc < 2) {
            printf("用法: wifi <SSID> <密码>\n");
            return;
        }
        if (store_set_wifi(argv[1], argc > 2 ? argv[2] : "") == ESP_OK) {
            printf("已保存 Wi-Fi，重启生效（reboot）\n");
        } else {
            printf("保存失败\n");
        }
    } else if (strcasecmp(argv[0], "ap") == 0) {
        totp_net_ap_start();
        printf("配网热点: %s\n密码: %s\n网址: %s\n", totp_net_ap_ssid(),
               totp_net_ap_password(), totp_net_ap_ip());
    } else if (strcasecmp(argv[0], "wifi-clear") == 0) {
        if (store_clear_wifi() == ESP_OK) {
            printf("已清除 Wi-Fi 凭据，下次开机进入配网模式\n");
        } else {
            printf("清除失败\n");
        }
    } else if (strcasecmp(argv[0], "reboot") == 0) {
        printf("重启中…\n");
        fflush(stdout);
        vTaskDelay(pdMS_TO_TICKS(200));
        esp_restart();
    } else {
        printf("未知命令: %s\n", argv[0]);
    }
}

static void console_task(void *arg)
{
    (void)arg;
    static char line[256];
    size_t length = 0;
    bool echo_seen = false;
    printf("\nTOTP 令牌串口控制台（help 查看命令）\n> ");
    fflush(stdout);
    while (true) {
        int ch = getchar();
        if (ch == EOF) {
            vTaskDelay(pdMS_TO_TICKS(30));
            continue;
        }
        if (ch == '\r') {
            continue;
        }
        if (ch == '\n') {
            line[length] = '\0';
            if (length > 0) {
                printf("\n");
                handle_line(line);
            }
            length = 0;
            echo_seen = false;
            printf("> ");
            fflush(stdout);
            continue;
        }
        if (ch == 0x7F || ch == 0x08) {
            if (length > 0) {
                length--;
            }
            continue;
        }
        if (length + 1 < sizeof(line)) {
            line[length++] = (char)ch;
        }
        echo_seen = true;
    }
}

void totp_console_start(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    xTaskCreate(console_task, "totp-console", 4096, NULL, 3, NULL);
    ESP_LOGI(TAG, "串口控制台已启动");
}
