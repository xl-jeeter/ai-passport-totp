#include "totp_app.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bsp_battery.h"
#include "bsp_button.h"
#include "bsp_display.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "misc/cache/instance/lv_image_cache.h"
#include "totp_core.h"
#include "totp_net.h"
#include "totp_store.h"

LV_FONT_DECLARE(totp_cjk_16);

static const char *TAG = "totp-app";

typedef struct {
    uint8_t button;
    uint8_t event;
} key_msg_t;

static QueueHandle_t s_key_queue;
static lv_obj_t *s_name_label;
static lv_obj_t *s_code_label;
static lv_obj_t *s_meta_label;
static lv_obj_t *s_hint_label;
static lv_obj_t *s_battery_label;
static lv_obj_t *s_ip_label;
static lv_obj_t *s_ap_label;
static lv_obj_t *s_icon_img;
static lv_image_dsc_t s_icon_dsc;
static uint8_t *s_icon_buf; /* 32×32 RGB565，堆上约 2 KB，只保留当前账号一份 */
static lv_obj_t *s_bar;
static lv_timer_t *s_timer;

static int s_index;
static bool s_hidden;
static int s_battery_tick;
static bool s_icon_loaded;
static int s_icon_loaded_index = -1;
static bool s_ap_shown;

static void refresh_account_locked(void);

/* 把当前账号的图标（若有）画到名字左侧。必须持 bsp_lvgl_lock()。 */
static void update_icon_locked(int index)
{
    if (s_icon_img == NULL) {
        return;
    }
    if (index < 0) {
        /* 无账号/无图标：无条件隐藏（s_icon_loaded 可能刚被 reload 清掉） */
        lv_obj_add_flag(s_icon_img, LV_OBJ_FLAG_HIDDEN);
        s_icon_loaded = false;
        s_icon_loaded_index = -1;
        return;
    }
    if (s_icon_loaded && s_icon_loaded_index == index) {
        return;
    }
    if (s_icon_buf != NULL && store_icon_get(index, s_icon_buf, TOTP_ICON_BYTES) == ESP_OK) {
        lv_image_cache_drop(&s_icon_dsc); /* 共享缓冲内容变了，丢弃旧缓存 */
        lv_image_set_src(s_icon_img, &s_icon_dsc);
        lv_obj_invalidate(s_icon_img);
        lv_obj_clear_flag(s_icon_img, LV_OBJ_FLAG_HIDDEN);
    } else {
        lv_obj_add_flag(s_icon_img, LV_OBJ_FLAG_HIDDEN);
    }
    s_icon_loaded = true;
    s_icon_loaded_index = index;
}

static void tick_cb(lv_timer_t *timer)
{
    (void)timer;
    totp_app_tick();
}

static const char *algo_short(uint8_t algo)
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

static void format_code(const char *digits_code, char *out, size_t out_len)
{
    size_t length = strlen(digits_code);
    if (length == 6) {
        snprintf(out, out_len, "%c%c%c %c%c%c", digits_code[0], digits_code[1], digits_code[2],
                 digits_code[3], digits_code[4], digits_code[5]);
    } else if (length == 8) {
        snprintf(out, out_len, "%c%c%c%c %c%c%c%c", digits_code[0], digits_code[1], digits_code[2],
                 digits_code[3], digits_code[4], digits_code[5], digits_code[6], digits_code[7]);
    } else {
        snprintf(out, out_len, "%s", digits_code);
    }
}

static void set_text(lv_obj_t *label, const char *text)
{
    if (label != NULL) {
        lv_label_set_text(label, text);
    }
}

static void refresh_account_locked(void)
{
    if (s_name_label == NULL) {
        return;
    }
    int total = store_count();
    if (total == 0) {
        set_text(s_name_label, "没有账号");
        set_text(s_code_label, "------");
        set_text(s_meta_label, "串口或网页添加账号");
        set_text(s_hint_label, "");
        update_icon_locked(-1);
        if (s_bar != NULL) {
            lv_bar_set_value(s_bar, 0, LV_ANIM_OFF);
        }
        return;
    }
    if (s_index < 0 || s_index >= total) {
        s_index = 0;
    }
    totp_account_t account;
    if (store_get(s_index, &account) != ESP_OK) {
        return;
    }
    set_text(s_name_label, account.name);
    update_icon_locked(s_index);

    char code[16] = "";
    char pretty[20] = "";
    uint8_t key[96];
    size_t key_len = 0;
    time_t now = time(NULL);
    bool time_ok = now > 1700000000;
    if (time_ok && base32_decode(account.secret, key, sizeof(key), &key_len) == 0 && key_len > 0 &&
        totp_code(key, key_len, totp_counter((uint64_t)now, account.period), account.digits,
                  account.algo, code, sizeof(code)) == 0) {
        format_code(code, pretty, sizeof(pretty));
    } else {
        snprintf(pretty, sizeof(pretty), time_ok ? "密钥错误" : "-- ---");
    }
    set_text(s_code_label, s_hidden && time_ok ? "- - -" : pretty);

    uint32_t remaining = time_ok ? totp_remaining((uint64_t)now, account.period) : 0;
    char meta[64];
    snprintf(meta, sizeof(meta), "%d/%d  ·  %s  ·  %us  ·  %lus", s_index + 1, total,
             algo_short(account.algo), (unsigned)account.period, (unsigned long)remaining);
    set_text(s_meta_label, meta);

    if (s_bar != NULL) {
        lv_bar_set_range(s_bar, 0, (int32_t)account.period);
        lv_bar_set_value(s_bar, (int32_t)remaining, LV_ANIM_OFF);
    }
    set_text(s_hint_label, s_hidden ? "OK 显示验证码" : "上下切换 · OK隐藏 · 长按授时");
}

void totp_app_tick(void)
{
    key_msg_t msg;
    while (s_key_queue != NULL && xQueueReceive(s_key_queue, &msg, 0) == pdTRUE) {
        if (!bsp_lvgl_lock(200)) {
            continue;
        }
        if (msg.event == BSP_BTN_CLICK) {
            if (msg.button == BSP_BTN_UP) {
                int total = store_count();
                if (total > 0) {
                    s_index = (s_index + total - 1) % total;
                }
            } else if (msg.button == BSP_BTN_DOWN) {
                int total = store_count();
                if (total > 0) {
                    s_index = (s_index + 1) % total;
                }
            } else if (msg.button == BSP_BTN_OK) {
                if (msg.event == BSP_BTN_LONG) {
                    totp_time_sync_request();
                } else {
                    s_hidden = !s_hidden;
                }
            }
        }
        refresh_account_locked();
        bsp_lvgl_unlock();
    }

    if (!bsp_lvgl_lock(50)) {
        return;
    }
    if (store_count() > 0) {
        refresh_account_locked();
    }
    bool ap = totp_net_is_ap();
    if (ap != s_ap_shown) {
        s_ap_shown = ap;
        /* AP 模式底部三行配网信息占位，普通提示与 IP 行让位 */
        if (s_ap_label != NULL) {
            if (ap) {
                lv_obj_clear_flag(s_ap_label, LV_OBJ_FLAG_HIDDEN);
            } else {
                lv_obj_add_flag(s_ap_label, LV_OBJ_FLAG_HIDDEN);
            }
        }
        if (s_hint_label != NULL) {
            if (ap) {
                lv_obj_add_flag(s_hint_label, LV_OBJ_FLAG_HIDDEN);
            } else {
                lv_obj_clear_flag(s_hint_label, LV_OBJ_FLAG_HIDDEN);
            }
        }
        if (s_ip_label != NULL) {
            if (ap) {
                lv_obj_add_flag(s_ip_label, LV_OBJ_FLAG_HIDDEN);
            } else {
                lv_obj_clear_flag(s_ip_label, LV_OBJ_FLAG_HIDDEN);
            }
        }
    }
    if (ap && s_ap_label != NULL) {
        char text[80];
        snprintf(text, sizeof(text), "热点: %s\n密码: %s\n网址: %s", totp_net_ap_ssid(),
                 totp_net_ap_password(), totp_net_ap_ip());
        if (strcmp(lv_label_get_text(s_ap_label), text) != 0) {
            lv_label_set_text(s_ap_label, text);
        }
    } else if (s_ip_label != NULL) {
        const char *ip = totp_net_ip();
        const char *text = (ip != NULL && ip[0] != '\0') ? ip : "未联网";
        if (strcmp(lv_label_get_text(s_ip_label), text) != 0) {
            lv_label_set_text(s_ip_label, text);
        }
    }
    if (++s_battery_tick % 20 == 0 && s_battery_label != NULL) {
        int soc = bsp_battery_soc();
        if (soc >= 0) {
            char text[12];
            snprintf(text, sizeof(text), "%d%%", soc);
            lv_label_set_text(s_battery_label, text);
        } else {
            lv_label_set_text(s_battery_label, "");
        }
    }
    bsp_lvgl_unlock();
}

void totp_app_reload(void)
{
    if (bsp_lvgl_lock(200)) {
        s_icon_loaded = false; /* 账号/图标可能已变化，强制重载 */
        refresh_account_locked();
        bsp_lvgl_unlock();
    }
}

void totp_app_time_synced(void)
{
    totp_app_reload();
}

static void style_screen(lv_obj_t *screen)
{
    lv_obj_set_style_bg_color(screen, lv_color_hex(0x0E1116), LV_PART_MAIN);
    lv_obj_set_style_bg_opa(screen, LV_OPA_COVER, LV_PART_MAIN);
    lv_obj_clear_flag(screen, LV_OBJ_FLAG_SCROLLABLE);
}

void totp_app_create(void)
{
    lv_obj_t *screen = lv_screen_active();
    style_screen(screen);

    /* 账户名（右侧让出图标位） */
    s_name_label = lv_label_create(screen);
    lv_obj_set_style_text_font(s_name_label, &totp_cjk_16, LV_PART_MAIN);
    lv_obj_set_style_text_color(s_name_label, lv_color_hex(0x8FA6C0), LV_PART_MAIN);
    lv_obj_align(s_name_label, LV_ALIGN_TOP_MID, 20, 26);
    lv_label_set_long_mode(s_name_label, LV_LABEL_LONG_DOT);
    lv_obj_set_width(s_name_label, 176);
    lv_obj_set_style_text_align(s_name_label, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);

    /* 账号图标：32×32 RGB565，画在名字左侧；无图标时隐藏 */
    s_icon_buf = malloc(TOTP_ICON_BYTES);
    if (s_icon_buf != NULL) {
        s_icon_dsc.header.magic = LV_IMAGE_HEADER_MAGIC;
        s_icon_dsc.header.cf = LV_COLOR_FORMAT_RGB565;
        s_icon_dsc.header.w = TOTP_ICON_DIM;
        s_icon_dsc.header.h = TOTP_ICON_DIM;
        s_icon_dsc.header.stride = TOTP_ICON_DIM * 2;
        s_icon_dsc.data_size = TOTP_ICON_BYTES;
        s_icon_dsc.data = s_icon_buf;
        s_icon_img = lv_image_create(screen);
        lv_image_set_src(s_icon_img, &s_icon_dsc);
        lv_obj_align(s_icon_img, LV_ALIGN_TOP_LEFT, 14, 22);
        lv_obj_add_flag(s_icon_img, LV_OBJ_FLAG_HIDDEN);
    } else {
        ESP_LOGW(TAG, "图标缓冲分配失败，界面不显示图标");
    }

    /* 电量（右上角） */
    s_battery_label = lv_label_create(screen);
    lv_obj_set_style_text_font(s_battery_label, &lv_font_montserrat_14, LV_PART_MAIN);
    lv_obj_set_style_text_color(s_battery_label, lv_color_hex(0x5A6B80), LV_PART_MAIN);
    lv_obj_align(s_battery_label, LV_ALIGN_TOP_RIGHT, -8, 6);
    lv_label_set_text(s_battery_label, "");

    /* 验证码 */
    s_code_label = lv_label_create(screen);
    lv_obj_set_style_text_font(s_code_label, &lv_font_montserrat_48, LV_PART_MAIN);
    lv_obj_set_style_text_color(s_code_label, lv_color_hex(0xE8F4FF), LV_PART_MAIN);
    lv_obj_align(s_code_label, LV_ALIGN_CENTER, 0, -34);
    lv_label_set_text(s_code_label, "-- ---");

    /* 倒计时进度条 */
    s_bar = lv_bar_create(screen);
    lv_obj_set_size(s_bar, 190, 8);
    lv_obj_align(s_bar, LV_ALIGN_CENTER, 0, 34);
    lv_bar_set_range(s_bar, 0, 30);
    lv_bar_set_value(s_bar, 30, LV_ANIM_OFF);
    lv_obj_set_style_bg_color(s_bar, lv_color_hex(0x1C2634), LV_PART_MAIN);
    lv_obj_set_style_bg_opa(s_bar, LV_OPA_COVER, LV_PART_MAIN);
    lv_obj_set_style_bg_color(s_bar, lv_color_hex(0x3BA7FF), LV_PART_INDICATOR);
    lv_obj_set_style_radius(s_bar, 4, LV_PART_MAIN);
    lv_obj_set_style_radius(s_bar, 4, LV_PART_INDICATOR);

    /* 元信息 */
    s_meta_label = lv_label_create(screen);
    lv_obj_set_style_text_font(s_meta_label, &totp_cjk_16, LV_PART_MAIN);
    lv_obj_set_style_text_color(s_meta_label, lv_color_hex(0x6C7F96), LV_PART_MAIN);
    lv_obj_align(s_meta_label, LV_ALIGN_CENTER, 0, 66);

    /* 操作提示 */
    s_hint_label = lv_label_create(screen);
    lv_obj_set_style_text_font(s_hint_label, &totp_cjk_16, LV_PART_MAIN);
    lv_obj_set_style_text_color(s_hint_label, lv_color_hex(0x47576B), LV_PART_MAIN);
    lv_obj_align(s_hint_label, LV_ALIGN_BOTTOM_MID, 0, -26);
    lv_obj_set_width(s_hint_label, 220);
    lv_obj_set_style_text_align(s_hint_label, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);

    /* 底部 IP：HTTP 后台入口提示 */
    s_ip_label = lv_label_create(screen);
    lv_obj_set_style_text_font(s_ip_label, &totp_cjk_16, LV_PART_MAIN);
    lv_obj_set_style_text_color(s_ip_label, lv_color_hex(0x5A6B80), LV_PART_MAIN);
    lv_obj_align(s_ip_label, LV_ALIGN_BOTTOM_MID, 0, -4);
    lv_label_set_text(s_ip_label, "未联网");

    /* 配网模式底部三行：热点/密码/网址（AP 模式下替换提示与 IP 行） */
    s_ap_label = lv_label_create(screen);
    lv_obj_set_style_text_font(s_ap_label, &totp_cjk_16, LV_PART_MAIN);
    lv_obj_set_style_text_color(s_ap_label, lv_color_hex(0x8FA6C0), LV_PART_MAIN);
    lv_obj_align(s_ap_label, LV_ALIGN_BOTTOM_MID, 0, -6);
    lv_obj_set_width(s_ap_label, 220);
    lv_obj_set_style_text_align(s_ap_label, LV_TEXT_ALIGN_CENTER, LV_PART_MAIN);
    lv_obj_add_flag(s_ap_label, LV_OBJ_FLAG_HIDDEN);

    if (s_key_queue == NULL) {
        s_key_queue = xQueueCreate(8, sizeof(key_msg_t));
    }
    if (s_timer == NULL) {
        s_timer = lv_timer_create(tick_cb, 250, NULL);
    }
    refresh_account_locked();
    ESP_LOGI(TAG, "TOTP 界面已创建，账号数 %d", store_count());
}

void totp_app_on_key(int button, int event)
{
    if (s_key_queue == NULL) {
        return;
    }
    key_msg_t msg = {.button = (uint8_t)button, .event = (uint8_t)event};
    if (xQueueSend(s_key_queue, &msg, 0) != pdTRUE) {
        ESP_LOGW(TAG, "按键队列已满，丢弃事件");
    }
}
