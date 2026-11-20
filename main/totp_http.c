#include "totp_http.h"

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "cJSON.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/base64.h"
#include "totp_app.h"
#include "totp_ap_proto.h"
#include "totp_core.h"
#include "totp_http_proto.h"
#include "totp_net.h"
#include "totp_store.h"

/* 请求体上限 16 KB：icon_b64 最长约 2732 字符，留足余量。 */
#define MAX_BODY 16384

static const char *TAG = "totp-http";

/* EMBED_TXTFILES 嵌入的单页后台（含结尾 NUL）。 */
extern const char totp_http_page_html_start[] asm("_binary_totp_http_page_html_start");
extern const char totp_http_page_html_end[] asm("_binary_totp_http_page_html_end");

static esp_err_t send_json(httpd_req_t *req, const char *status, const char *body)
{
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t send_ok(httpd_req_t *req)
{
    return send_json(req, "200 OK", "{\"ok\":true}");
}

static esp_err_t send_error(httpd_req_t *req, const char *status, const char *message)
{
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return send_json(req, status, "{\"ok\":false}");
    }
    cJSON_AddBoolToObject(root, "ok", false);
    cJSON_AddStringToObject(root, "error", message);
    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    esp_err_t err = send_json(req, status, body != NULL ? body : "{\"ok\":false}");
    cJSON_free(body);
    return err;
}

/* 读请求体（malloc，调用方 free）。失败时 status 与 fail 指针给出应答。 */
static char *read_body(httpd_req_t *req, const char **status, const char **fail)
{
    *status = "400 Bad Request";
    *fail = "bad request";
    int total = (int)req->content_len;
    if (total <= 0) {
        *fail = "empty request body";
        return NULL;
    }
    if (total > MAX_BODY) {
        *status = "413 Payload Too Large";
        *fail = "request body too large (max 16KB)";
        return NULL;
    }
    char *buf = malloc((size_t)total + 1);
    if (buf == NULL) {
        *status = "500 Internal Server Error";
        *fail = "out of memory";
        return NULL;
    }
    int received = 0;
    int timeouts = 0;
    while (received < total) {
        int ret = httpd_req_recv(req, buf + received, total - received);
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            if (++timeouts > 3) {
                free(buf);
                *fail = "receive timeout";
                return NULL;
            }
            continue;
        }
        if (ret <= 0) {
            free(buf);
            *fail = "receive failed";
            return NULL;
        }
        timeouts = 0;
        received += ret;
    }
    buf[total] = '\0';
    return buf;
}

static bool icon_decode(const char *b64, uint8_t *out)
{
    size_t olen = 0;
    int ret = mbedtls_base64_decode(out, TOTP_ICON_BYTES, &olen,
                                    (const unsigned char *)b64, strlen(b64));
    return ret == 0 && olen == TOTP_ICON_BYTES;
}

/* 当前验证码（十进制字符串）；无法计算时输出空串。 */
static void current_code(const totp_account_t *account, char *out, size_t out_len)
{
    out[0] = '\0';
    time_t now = time(NULL);
    uint8_t key[96];
    size_t key_len = 0;
    if (now > 1700000000 &&
        base32_decode(account->secret, key, sizeof(key), &key_len) == 0 && key_len > 0 &&
        totp_code(key, key_len, totp_counter((uint64_t)now, account->period),
                  account->digits, account->algo, out, out_len) == 0) {
        return;
    }
    out[0] = '\0';
}

static esp_err_t handle_page(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_send(req, totp_http_page_html_start, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t handle_status(httpd_req_t *req)
{
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return send_error(req, "500 Internal Server Error", "out of memory");
    }
    cJSON_AddStringToObject(root, "ip", totp_net_ip());
    cJSON_AddNumberToObject(root, "accounts", store_count());
    cJSON_AddBoolToObject(root, "time_ok", totp_time_ready());
    cJSON_AddNumberToObject(root, "uptime", (double)(esp_timer_get_time() / 1000000));
    cJSON_AddBoolToObject(root, "ap", totp_net_is_ap());
    if (totp_net_is_ap()) {
        cJSON_AddStringToObject(root, "ap_ssid", totp_net_ap_ssid());
        cJSON_AddStringToObject(root, "ap_ip", totp_net_ap_ip());
    }
    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    esp_err_t err = send_json(req, "200 OK", body != NULL ? body : "{}");
    cJSON_free(body);
    return err;
}

static esp_err_t handle_accounts_get(httpd_req_t *req)
{
    cJSON *array = cJSON_CreateArray();
    if (array == NULL) {
        return send_error(req, "500 Internal Server Error", "out of memory");
    }
    int total = store_count();
    for (int i = 0; i < total; i++) {
        totp_account_t account;
        if (store_get(i, &account) != ESP_OK) {
            continue;
        }
        cJSON *item = cJSON_CreateObject();
        if (item == NULL) {
            continue;
        }
        cJSON_AddNumberToObject(item, "index", i);
        cJSON_AddStringToObject(item, "name", account.name);
        cJSON_AddNumberToObject(item, "digits", account.digits);
        cJSON_AddNumberToObject(item, "period", account.period);
        cJSON_AddStringToObject(item, "algo", totp_proto_algo_name(account.algo));
        cJSON_AddBoolToObject(item, "has_icon", store_icon_has(i));
        char code[16];
        current_code(&account, code, sizeof(code));
        cJSON_AddStringToObject(item, "code", code);
        cJSON_AddItemToArray(array, item);
    }
    char *body = cJSON_PrintUnformatted(array);
    cJSON_Delete(array);
    esp_err_t err = send_json(req, "200 OK", body != NULL ? body : "[]");
    cJSON_free(body);
    return err;
}

/* 取出请求里的 icon_b64：*icon 为 malloc 的 TOTP_ICON_BYTES 缓冲（调用方 free），
 * 无图标时 *icon == NULL。字段非法时返回 false 并给出错误信息。 */
static bool take_icon(const cJSON *jicon, uint8_t **icon, const char **fail)
{
    *icon = NULL;
    if (jicon == NULL) {
        return true; /* 未提供：不动图标 */
    }
    if (!cJSON_IsString(jicon) || jicon->valuestring[0] == '\0') {
        return true; /* 显式置空：调用方按“清除图标”处理（用 icon_present 区分） */
    }
    uint8_t *buf = malloc(TOTP_ICON_BYTES);
    if (buf == NULL) {
        *fail = "out of memory";
        return false;
    }
    if (!icon_decode(jicon->valuestring, buf)) {
        free(buf);
        *fail = "invalid icon_b64 (expect base64 of 2048-byte 32x32 RGB565 little-endian)";
        return false;
    }
    *icon = buf;
    return true;
}

static esp_err_t handle_account_create(httpd_req_t *req)
{
    const char *status = NULL;
    const char *fail = NULL;
    char *body = read_body(req, &status, &fail);
    if (body == NULL) {
        return send_error(req, status, fail);
    }
    cJSON *root = cJSON_Parse(body);
    free(body);
    if (root == NULL) {
        return send_error(req, "400 Bad Request", "invalid JSON");
    }

    const cJSON *jname = cJSON_GetObjectItemCaseSensitive(root, "name");
    const cJSON *jsecret = cJSON_GetObjectItemCaseSensitive(root, "secret");
    const cJSON *jdigits = cJSON_GetObjectItemCaseSensitive(root, "digits");
    const cJSON *jperiod = cJSON_GetObjectItemCaseSensitive(root, "period");
    const cJSON *jalgo = cJSON_GetObjectItemCaseSensitive(root, "algo");
    const cJSON *jicon = cJSON_GetObjectItemCaseSensitive(root, "icon_b64");

    if (!cJSON_IsString(jname) || !cJSON_IsString(jsecret) ||
        strlen(jname->valuestring) >= TOTP_NAME_LEN ||
        strlen(jsecret->valuestring) >= TOTP_SECRET_LEN) {
        cJSON_Delete(root);
        return send_error(req, "400 Bad Request",
                          "need name(<32) and secret(<128) as strings");
    }
    int algo = -1;
    if (cJSON_IsString(jalgo)) {
        algo = totp_proto_algo_from_name(jalgo->valuestring);
        if (algo < 0) {
            cJSON_Delete(root);
            return send_error(req, "400 Bad Request", "algo must be SHA1/SHA256/SHA512");
        }
    }
    int digits = cJSON_IsNumber(jdigits) ? jdigits->valueint : 0;
    int period = cJSON_IsNumber(jperiod) ? jperiod->valueint : 0;
    int out_digits = 0;
    int out_period = 0;
    int out_algo = 0;
    if (!totp_proto_account_fields(jname->valuestring, jsecret->valuestring,
                                   digits, period, algo,
                                   &out_digits, &out_period, &out_algo)) {
        cJSON_Delete(root);
        return send_error(req, "400 Bad Request",
                          "invalid fields (digits 6-8, period 10-120, secret must be base32)");
    }

    uint8_t *icon = NULL;
    if (!take_icon(jicon, &icon, &fail)) {
        cJSON_Delete(root);
        return send_error(req, "400 Bad Request", fail);
    }

    totp_account_t account = {0};
    snprintf(account.name, sizeof(account.name), "%s", jname->valuestring);
    snprintf(account.secret, sizeof(account.secret), "%s", jsecret->valuestring);
    account.digits = (uint8_t)out_digits;
    account.period = (uint16_t)out_period;
    account.algo = (uint8_t)out_algo;

    int new_index = -1;
    esp_err_t err = store_add(&account, &new_index);
    if (err == ESP_OK && icon != NULL) {
        err = store_icon_set(new_index, icon, TOTP_ICON_BYTES);
    }
    free(icon);
    cJSON_Delete(root);
    if (err != ESP_OK) {
        return send_error(req, err == ESP_ERR_NO_MEM ? "400 Bad Request" : "500 Internal Server Error",
                          err == ESP_ERR_NO_MEM ? "account limit reached" : "save failed");
    }
    totp_app_reload();
    return send_ok(req);
}

static esp_err_t handle_account_update(httpd_req_t *req)
{
    int index = totp_proto_account_index(req->uri, store_count());
    if (index < 0) {
        return send_error(req, "404 Not Found", "no such account");
    }
    const char *status = NULL;
    const char *fail = NULL;
    char *body = read_body(req, &status, &fail);
    if (body == NULL) {
        return send_error(req, status, fail);
    }
    cJSON *root = cJSON_Parse(body);
    free(body);
    if (root == NULL) {
        return send_error(req, "400 Bad Request", "invalid JSON");
    }
    totp_account_t account;
    if (store_get(index, &account) != ESP_OK) {
        cJSON_Delete(root);
        return send_error(req, "404 Not Found", "no such account");
    }

    /* 合并更新：缺省字段保留原值 */
    const cJSON *jname = cJSON_GetObjectItemCaseSensitive(root, "name");
    const cJSON *jsecret = cJSON_GetObjectItemCaseSensitive(root, "secret");
    const cJSON *jdigits = cJSON_GetObjectItemCaseSensitive(root, "digits");
    const cJSON *jperiod = cJSON_GetObjectItemCaseSensitive(root, "period");
    const cJSON *jalgo = cJSON_GetObjectItemCaseSensitive(root, "algo");
    const cJSON *jicon = cJSON_GetObjectItemCaseSensitive(root, "icon_b64");

    if (cJSON_IsString(jname)) {
        if (strlen(jname->valuestring) >= TOTP_NAME_LEN) {
            cJSON_Delete(root);
            return send_error(req, "400 Bad Request", "name too long (max 31)");
        }
        snprintf(account.name, sizeof(account.name), "%s", jname->valuestring);
    }
    if (cJSON_IsString(jsecret)) {
        if (strlen(jsecret->valuestring) >= TOTP_SECRET_LEN) {
            cJSON_Delete(root);
            return send_error(req, "400 Bad Request", "secret too long (max 127)");
        }
        snprintf(account.secret, sizeof(account.secret), "%s", jsecret->valuestring);
    }
    int digits = cJSON_IsNumber(jdigits) ? jdigits->valueint : account.digits;
    int period = cJSON_IsNumber(jperiod) ? jperiod->valueint : account.period;
    int algo = account.algo;
    if (cJSON_IsString(jalgo)) {
        algo = totp_proto_algo_from_name(jalgo->valuestring);
        if (algo < 0) {
            cJSON_Delete(root);
            return send_error(req, "400 Bad Request", "algo must be SHA1/SHA256/SHA512");
        }
    }
    int out_digits = 0;
    int out_period = 0;
    int out_algo = 0;
    if (!totp_proto_account_fields(account.name, account.secret,
                                   digits, period, algo,
                                   &out_digits, &out_period, &out_algo)) {
        cJSON_Delete(root);
        return send_error(req, "400 Bad Request",
                          "invalid fields (digits 6-8, period 10-120, secret must be base32)");
    }
    account.digits = (uint8_t)out_digits;
    account.period = (uint16_t)out_period;
    account.algo = (uint8_t)out_algo;

    uint8_t *icon = NULL;
    if (!take_icon(jicon, &icon, &fail)) {
        cJSON_Delete(root);
        return send_error(req, "400 Bad Request", fail);
    }

    esp_err_t err = store_update(index, &account);
    if (err == ESP_OK && jicon != NULL) {
        if (icon != NULL) {
            err = store_icon_set(index, icon, TOTP_ICON_BYTES);
        } else {
            err = store_icon_erase(index); /* icon_b64 为空串/ null：清除图标 */
        }
    }
    free(icon);
    cJSON_Delete(root);
    if (err != ESP_OK) {
        return send_error(req, "500 Internal Server Error", "save failed");
    }
    totp_app_reload();
    return send_ok(req);
}

static esp_err_t handle_account_delete(httpd_req_t *req)
{
    int index = totp_proto_account_index(req->uri, store_count());
    if (index < 0) {
        return send_error(req, "404 Not Found", "no such account");
    }
    if (store_delete(index) != ESP_OK) {
        return send_error(req, "500 Internal Server Error", "delete failed");
    }
    totp_app_reload();
    return send_ok(req);
}

static esp_err_t handle_time(httpd_req_t *req)
{
    const char *status = NULL;
    const char *fail = NULL;
    char *body = read_body(req, &status, &fail);
    if (body == NULL) {
        return send_error(req, status, fail);
    }
    cJSON *root = cJSON_Parse(body);
    free(body);
    if (root == NULL) {
        return send_error(req, "400 Bad Request", "invalid JSON");
    }
    const cJSON *jepoch = cJSON_GetObjectItemCaseSensitive(root, "epoch");
    double epoch = cJSON_IsNumber(jepoch) ? jepoch->valuedouble : 0;
    cJSON_Delete(root);
    if (epoch < 1000000000.0 || epoch > 4102444800.0) { /* 2001..2100 */
        return send_error(req, "400 Bad Request", "epoch must be a unix timestamp in seconds");
    }
    struct timeval tv = {.tv_sec = (time_t)epoch, .tv_usec = 0};
    settimeofday(&tv, NULL);
    totp_app_time_synced();
    ESP_LOGI(TAG, "网页授时：%lld", (long long)tv.tv_sec);
    return send_ok(req);
}

static esp_err_t handle_wifi_scan(httpd_req_t *req)
{
    totp_wifi_scan_item_t items[20];
    int count = totp_net_wifi_scan(items, (int)(sizeof(items) / sizeof(items[0])));
    if (count < 0) {
        return send_error(req, "500 Internal Server Error", "scan failed");
    }
    cJSON *array = cJSON_CreateArray();
    if (array == NULL) {
        return send_error(req, "500 Internal Server Error", "out of memory");
    }
    for (int i = 0; i < count; i++) {
        cJSON *item = cJSON_CreateObject();
        if (item == NULL) {
            continue;
        }
        cJSON_AddStringToObject(item, "ssid", items[i].ssid);
        cJSON_AddNumberToObject(item, "rssi", items[i].rssi);
        cJSON_AddStringToObject(item, "auth", items[i].auth);
        cJSON_AddItemToArray(array, item);
    }
    char *json = cJSON_PrintUnformatted(array);
    cJSON_Delete(array);
    esp_err_t err = send_json(req, "200 OK", json != NULL ? json : "[]");
    cJSON_free(json);
    return err;
}

static esp_err_t handle_wifi(httpd_req_t *req)
{
    const char *status = NULL;
    const char *fail = NULL;
    char *body = read_body(req, &status, &fail);
    if (body == NULL) {
        return send_error(req, status, fail);
    }
    cJSON *root = cJSON_Parse(body);
    free(body);
    if (root == NULL) {
        return send_error(req, "400 Bad Request", "invalid JSON");
    }
    const cJSON *jssid = cJSON_GetObjectItemCaseSensitive(root, "ssid");
    const cJSON *jpass = cJSON_GetObjectItemCaseSensitive(root, "password");
    if (!cJSON_IsString(jssid) || jssid->valuestring[0] == '\0' ||
        strlen(jssid->valuestring) > 32 ||
        (cJSON_IsString(jpass) && strlen(jpass->valuestring) > 64)) {
        cJSON_Delete(root);
        return send_error(req, "400 Bad Request", "need ssid (<=32) and password (<=64)");
    }
    char ssid[33];
    char password[65] = {0};
    snprintf(ssid, sizeof(ssid), "%s", jssid->valuestring);
    if (cJSON_IsString(jpass)) {
        snprintf(password, sizeof(password), "%s", jpass->valuestring);
    }
    cJSON_Delete(root);

    if (totp_net_is_ap()) {
        /* 配网模式：保存后立即试连（最多 20 秒），不重启 */
        char ip[16] = {0};
        char error[64] = {0};
        if (totp_net_sta_try(ssid, password, ip, sizeof(ip), error, sizeof(error)) != ESP_OK) {
            return send_error(req, "502 Bad Gateway",
                              error[0] != '\0' ? error : "connect failed");
        }
        cJSON *reply = cJSON_CreateObject();
        if (reply == NULL) {
            return send_error(req, "500 Internal Server Error", "out of memory");
        }
        cJSON_AddBoolToObject(reply, "ok", true);
        cJSON_AddStringToObject(reply, "ip", ip);
        char *json = cJSON_PrintUnformatted(reply);
        cJSON_Delete(reply);
        esp_err_t sent = send_json(req, "200 OK", json != NULL ? json : "{\"ok\":true}");
        cJSON_free(json);
        ESP_LOGI(TAG, "已连接 %s（%s），2 秒后关闭配网热点", ssid, ip);
        vTaskDelay(pdMS_TO_TICKS(2000)); /* 让应答先发出去 */
        totp_net_ap_stop();
        return sent;
    }

    /* STA 模式保持既有契约：保存后重启生效 */
    esp_err_t err = store_set_wifi(ssid, password);
    if (err != ESP_OK) {
        return send_error(req, "500 Internal Server Error", "save failed");
    }
    esp_err_t sent = send_ok(req);
    ESP_LOGI(TAG, "Wi-Fi 已保存，2 秒后重启生效");
    vTaskDelay(pdMS_TO_TICKS(2000)); /* 让应答先发出去 */
    esp_restart();
    return sent;
}

/* 未知路径兜底：配网模式下配合 DNS 全应答实现 Captive Portal 自动弹页。
 * 必须最后注册（通配路径命中一切，注册顺序即匹配顺序）。 */
static esp_err_t handle_catch_all(httpd_req_t *req)
{
    if (!totp_net_is_ap()) {
        return send_error(req, "404 Not Found", "not found");
    }
    if (strncmp(req->uri, "/api/", 5) == 0) {
        return send_error(req, "404 Not Found", "no such API");
    }
    if (totp_captive_path(req->uri)) {
        /* 系统探测路径：302 到配置页（Location 必须绝对地址，否则会被
         * 解析回探测域名）。其余未知路径直接给配置页。 */
        static char location[32];
        snprintf(location, sizeof(location), "http://%s/", totp_net_ap_ip());
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", location);
        return httpd_resp_send(req, NULL, 0);
    }
    return handle_page(req);
}

static void register_uri(httpd_handle_t server, const char *uri, httpd_method_t method,
                         esp_err_t (*handler)(httpd_req_t *))
{
    httpd_uri_t config = {
        .uri = uri,
        .method = method,
        .handler = handler,
        .user_ctx = NULL,
    };
    if (httpd_register_uri_handler(server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "注册处理器失败: %s", uri);
    }
}

void totp_http_start(void)
{
    static bool s_started;
    if (s_started) {
        return;
    }
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.stack_size = 8192;
    config.max_uri_handlers = 12;
    config.max_open_sockets = 4;
    config.lru_purge_enable = true;
    config.uri_match_fn = httpd_uri_match_wildcard;

    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "HTTP 后台启动失败");
        return;
    }
    register_uri(server, "/", HTTP_GET, handle_page);
    register_uri(server, "/api/status", HTTP_GET, handle_status);
    register_uri(server, "/api/accounts", HTTP_GET, handle_accounts_get);
    register_uri(server, "/api/accounts", HTTP_POST, handle_account_create);
    register_uri(server, "/api/accounts/*", HTTP_PUT, handle_account_update);
    register_uri(server, "/api/accounts/*", HTTP_DELETE, handle_account_delete);
    register_uri(server, "/api/time", HTTP_POST, handle_time);
    register_uri(server, "/api/wifi", HTTP_POST, handle_wifi);
    register_uri(server, "/api/wifi/scan", HTTP_GET, handle_wifi_scan);
    register_uri(server, "/*", HTTP_GET, handle_catch_all); /* 通配兜底，必须最后 */
    s_started = true;
    ESP_LOGI(TAG, "HTTP 后台已启动（端口 80）");
}
