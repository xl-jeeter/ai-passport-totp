#include "totp_store.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"
#include "nvs_flash.h"

static const char *TAG = "store";
static const char *NAMESPACE = "totp";
static nvs_handle_t s_handle;
static bool s_ready;
/* 串口、HTTP、界面三个上下文都会读写账号，用递归互斥串行化。
 * 嵌套调用（如 store_delete 内部用 store_get）依赖递归语义。 */
static SemaphoreHandle_t s_lock;
static uint8_t s_icon_scratch[TOTP_ICON_BYTES];

static void store_lock(void)
{
    if (s_lock != NULL) {
        xSemaphoreTakeRecursive(s_lock, portMAX_DELAY);
    }
}

static void store_unlock(void)
{
    if (s_lock != NULL) {
        xSemaphoreGiveRecursive(s_lock);
    }
}

static void key_for(char *buffer, size_t size, const char *prefix, int index)
{
    snprintf(buffer, size, "%s%d", prefix, index);
}

static esp_err_t icon_read_locked(int index, void *out, size_t len)
{
    if (!s_ready || out == NULL || len != TOTP_ICON_BYTES || index < 0 || index >= TOTP_MAX_ACCOUNTS) {
        return ESP_ERR_INVALID_ARG;
    }
    char key[12];
    key_for(key, sizeof(key), "i", index);
    size_t length = len;
    return nvs_get_blob(s_handle, key, out, &length);
}

static esp_err_t icon_write_locked(int index, const void *data, size_t len)
{
    if (!s_ready || data == NULL || len != TOTP_ICON_BYTES || index < 0 || index >= TOTP_MAX_ACCOUNTS) {
        return ESP_ERR_INVALID_ARG;
    }
    char key[12];
    key_for(key, sizeof(key), "i", index);
    return nvs_set_blob(s_handle, key, data, len);
}

static esp_err_t icon_erase_locked(int index)
{
    if (!s_ready || index < 0 || index >= TOTP_MAX_ACCOUNTS) {
        return ESP_ERR_INVALID_ARG;
    }
    char key[12];
    key_for(key, sizeof(key), "i", index);
    nvs_erase_key(s_handle, key); /* 不存在也无妨 */
    return ESP_OK;
}

static esp_err_t account_write_locked(int index, const totp_account_t *account)
{
    char key[12];
    key_for(key, sizeof(key), "n", index);
    esp_err_t err = nvs_set_str(s_handle, key, account->name);
    if (err != ESP_OK) {
        return err;
    }
    key_for(key, sizeof(key), "s", index);
    err = nvs_set_str(s_handle, key, account->secret);
    if (err != ESP_OK) {
        return err;
    }
    key_for(key, sizeof(key), "d", index);
    nvs_set_u8(s_handle, key, account->digits);
    key_for(key, sizeof(key), "p", index);
    nvs_set_u16(s_handle, key, account->period);
    key_for(key, sizeof(key), "a", index);
    nvs_set_u8(s_handle, key, account->algo);
    return ESP_OK;
}

static void account_erase_locked(int index)
{
    char key[12];
    key_for(key, sizeof(key), "n", index);
    nvs_erase_key(s_handle, key);
    key_for(key, sizeof(key), "s", index);
    nvs_erase_key(s_handle, key);
    key_for(key, sizeof(key), "d", index);
    nvs_erase_key(s_handle, key);
    key_for(key, sizeof(key), "p", index);
    nvs_erase_key(s_handle, key);
    key_for(key, sizeof(key), "a", index);
    nvs_erase_key(s_handle, key);
}

esp_err_t store_init(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        return err;
    }
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateRecursiveMutex();
    }
    err = nvs_open(NAMESPACE, NVS_READWRITE, &s_handle);
    if (err == ESP_OK) {
        s_ready = true;
    }
    return err;
}

int store_count(void)
{
    store_lock();
    int count = 0;
    if (s_ready) {
        uint8_t value = 0;
        if (nvs_get_u8(s_handle, "count", &value) == ESP_OK) {
            count = value > TOTP_MAX_ACCOUNTS ? TOTP_MAX_ACCOUNTS : value;
        }
    }
    store_unlock();
    return count;
}

esp_err_t store_get(int index, totp_account_t *out)
{
    store_lock();
    esp_err_t err = ESP_ERR_INVALID_ARG;
    if (!s_ready || out == NULL || index < 0 || index >= store_count()) {
        store_unlock();
        return err;
    }
    char key[12];
    size_t length = sizeof(out->name);
    key_for(key, sizeof(key), "n", index);
    err = nvs_get_str(s_handle, key, out->name, &length);
    if (err != ESP_OK) {
        store_unlock();
        return err;
    }
    length = sizeof(out->secret);
    key_for(key, sizeof(key), "s", index);
    err = nvs_get_str(s_handle, key, out->secret, &length);
    if (err != ESP_OK) {
        store_unlock();
        return err;
    }
    out->digits = 6;
    out->period = 30;
    out->algo = 0;
    key_for(key, sizeof(key), "d", index);
    nvs_get_u8(s_handle, key, &out->digits);
    key_for(key, sizeof(key), "p", index);
    nvs_get_u16(s_handle, key, &out->period);
    key_for(key, sizeof(key), "a", index);
    nvs_get_u8(s_handle, key, &out->algo);
    if (out->digits < 6 || out->digits > 8) {
        out->digits = 6;
    }
    if (out->period == 0) {
        out->period = 30;
    }
    store_unlock();
    return ESP_OK;
}

esp_err_t store_add(const totp_account_t *account, int *out_index)
{
    if (account == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    store_lock();
    esp_err_t err = ESP_ERR_INVALID_ARG;
    if (!s_ready) {
        store_unlock();
        return err;
    }
    int index = store_count();
    if (index >= TOTP_MAX_ACCOUNTS) {
        store_unlock();
        return ESP_ERR_NO_MEM;
    }
    err = account_write_locked(index, account);
    if (err == ESP_OK) {
        nvs_set_u8(s_handle, "count", (uint8_t)(index + 1));
        err = nvs_commit(s_handle);
        if (out_index != NULL) {
            *out_index = index;
        }
        ESP_LOGI(TAG, "已保存账号 %s（共 %d 个）", account->name, index + 1);
    }
    store_unlock();
    return err;
}

esp_err_t store_update(int index, const totp_account_t *account)
{
    if (account == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    store_lock();
    esp_err_t err = ESP_ERR_INVALID_ARG;
    if (!s_ready || index < 0 || index >= store_count()) {
        store_unlock();
        return err;
    }
    err = account_write_locked(index, account);
    if (err == ESP_OK) {
        err = nvs_commit(s_handle);
        ESP_LOGI(TAG, "已更新账号 #%d %s", index, account->name);
    }
    store_unlock();
    return err;
}

esp_err_t store_delete(int index)
{
    store_lock();
    esp_err_t err = ESP_ERR_INVALID_ARG;
    if (!s_ready || index < 0 || index >= store_count()) {
        store_unlock();
        return err;
    }
    // 简单做法：把后面的账号前移，保证下标连续；图标跟随账号一起搬动
    int total = store_count();
    for (int i = index; i < total - 1; i++) {
        totp_account_t next;
        if (store_get(i + 1, &next) != ESP_OK) {
            store_unlock();
            return ESP_FAIL;
        }
        err = account_write_locked(i, &next);
        if (err != ESP_OK) {
            store_unlock();
            return err;
        }
        if (icon_read_locked(i + 1, s_icon_scratch, TOTP_ICON_BYTES) == ESP_OK) {
            icon_write_locked(i, s_icon_scratch, TOTP_ICON_BYTES);
        } else {
            icon_erase_locked(i);
        }
    }
    account_erase_locked(total - 1);
    icon_erase_locked(total - 1);
    nvs_set_u8(s_handle, "count", (uint8_t)(total - 1));
    err = nvs_commit(s_handle);
    store_unlock();
    return err;
}

esp_err_t store_find(const char *name_or_index, int *index)
{
    if (name_or_index == NULL || index == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    char *end = NULL;
    long parsed = strtol(name_or_index, &end, 10);
    if (end != name_or_index && *end == '\0') {
        if (parsed < 0 || parsed >= store_count()) {
            return ESP_ERR_NOT_FOUND;
        }
        *index = (int)parsed;
        return ESP_OK;
    }
    int total = store_count();
    for (int i = 0; i < total; i++) {
        totp_account_t account;
        if (store_get(i, &account) == ESP_OK && strcmp(account.name, name_or_index) == 0) {
            *index = i;
            return ESP_OK;
        }
    }
    return ESP_ERR_NOT_FOUND;
}

bool store_icon_has(int index)
{
    store_lock();
    bool has = false;
    if (s_ready && index >= 0 && index < store_count()) {
        has = icon_read_locked(index, s_icon_scratch, TOTP_ICON_BYTES) == ESP_OK;
    }
    store_unlock();
    return has;
}

esp_err_t store_icon_get(int index, void *out, size_t len)
{
    store_lock();
    esp_err_t err = icon_read_locked(index, out, len);
    store_unlock();
    return err;
}

esp_err_t store_icon_set(int index, const void *data, size_t len)
{
    store_lock();
    esp_err_t err = ESP_ERR_INVALID_ARG;
    if (!s_ready || data == NULL || len != TOTP_ICON_BYTES || index < 0 || index >= store_count()) {
        store_unlock();
        return err;
    }
    err = icon_write_locked(index, data, len);
    if (err == ESP_OK) {
        err = nvs_commit(s_handle);
    }
    store_unlock();
    return err;
}

esp_err_t store_icon_erase(int index)
{
    store_lock();
    esp_err_t err = icon_erase_locked(index);
    if (err == ESP_OK) {
        err = nvs_commit(s_handle);
    }
    store_unlock();
    return err;
}

esp_err_t store_set_wifi(const char *ssid, const char *password)
{
    if (!s_ready || ssid == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    store_lock();
    esp_err_t err = nvs_set_str(s_handle, "wifi_ssid", ssid);
    if (err == ESP_OK && password != NULL) {
        err = nvs_set_str(s_handle, "wifi_pass", password);
    }
    if (err == ESP_OK) {
        err = nvs_commit(s_handle);
    }
    store_unlock();
    return err;
}

esp_err_t store_clear_wifi(void)
{
    if (!s_ready) {
        return ESP_ERR_INVALID_STATE;
    }
    store_lock();
    nvs_erase_key(s_handle, "wifi_ssid"); /* 不存在也无妨 */
    nvs_erase_key(s_handle, "wifi_pass");
    esp_err_t err = nvs_commit(s_handle);
    store_unlock();
    return err;
}

esp_err_t store_get_wifi(char *ssid, size_t ssid_len, char *password, size_t password_len)
{
    if (!s_ready || ssid == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    store_lock();
    size_t length = ssid_len;
    esp_err_t err = nvs_get_str(s_handle, "wifi_ssid", ssid, &length);
    if (err != ESP_OK) {
        store_unlock();
        return err;
    }
    if (password != NULL) {
        length = password_len;
        if (nvs_get_str(s_handle, "wifi_pass", password, &length) != ESP_OK) {
            password[0] = '\0';
        }
    }
    store_unlock();
    return err;
}
