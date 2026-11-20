#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#define TOTP_MAX_ACCOUNTS 16
#define TOTP_NAME_LEN 32
#define TOTP_SECRET_LEN 128

/* 账号图标：32×32 RGB565（小端）原始数据，2048 字节，存 NVS blob。 */
#define TOTP_ICON_DIM 32
#define TOTP_ICON_BYTES (TOTP_ICON_DIM * TOTP_ICON_DIM * 2)

typedef struct {
    char name[TOTP_NAME_LEN];
    char secret[TOTP_SECRET_LEN]; /* base32 原文，NVS 里也是它 */
    uint8_t digits;
    uint16_t period;
    uint8_t algo; /* 0=SHA1 1=SHA256 2=SHA512 */
} totp_account_t;

esp_err_t store_init(void);
int store_count(void);
esp_err_t store_get(int index, totp_account_t *out);
esp_err_t store_add(const totp_account_t *account, int *out_index); /* out_index 可 NULL */
esp_err_t store_update(int index, const totp_account_t *account);
esp_err_t store_delete(int index);
esp_err_t store_find(const char *name_or_index, int *index);

/* 账号图标（每个账号最多一个，随账号删除/前移一起搬动）。 */
bool store_icon_has(int index);
esp_err_t store_icon_get(int index, void *out, size_t len); /* len 须为 TOTP_ICON_BYTES */
esp_err_t store_icon_set(int index, const void *data, size_t len);
esp_err_t store_icon_erase(int index);

/* Wi-Fi 凭据 */
esp_err_t store_set_wifi(const char *ssid, const char *password);
esp_err_t store_get_wifi(char *ssid, size_t ssid_len, char *password, size_t password_len);
esp_err_t store_clear_wifi(void); /* 清除已保存凭据（下次开机进配网模式） */
