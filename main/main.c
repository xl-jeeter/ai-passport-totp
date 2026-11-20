/*
 * 暮光令牌 —— FoloToy AI Passport 上的 TOTP 硬件验证器。
 *
 * 与仓库自带的 BSP 测试 demo 不同，本应用有独立的界面与交互：
 *   - 深色主屏：大号 6 位验证码 + 倒计时进度条 + 账号名 + 电量
 *   - 上/下：切换账号；OK 短按：隐藏/显示验证码；OK 长按：重新校时
 *   - 时间：Wi-Fi + SNTP，或串口 time <epoch> 手动授时
 *   - 密钥：NVS 存储，永不外传；串口 addurl/add 或局域网网页后台导入
 *   - 联网：无凭据或连不上时开 SoftAP 热点（TOTP-XXXX），手机连热点自动弹配网页
 *   - 联网后屏幕底部显示本机 IP，浏览器访问可管理账号（含图标上传）
 */
#include <stdio.h>

#include "bsp_battery.h"
#include "bsp_button.h"
#include "bsp_display.h"
#include "bsp_i2c.h"
#include "bsp_pins.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "key_guard.h"
#include "totp_app.h"
#include "totp_console.h"
#include "totp_net.h"
#include "totp_store.h"

static const char *TAG = "main";

/* 上电/唤醒时按键可能仍按着：按键组件晚几百毫秒才启动，会把已按住的电平判成长按
 * 并立刻触发动作。守卫吞掉按键动作直到松手（状态机见 key_guard.h）。 */
#define KEY_GUARD_MAX_US (10LL * 1000 * 1000)
static key_guard_t s_key_guard;
static volatile bool s_input_ready;

/* button 回调运行在共享 esp_timer 任务上：只投递事件，不碰 LVGL。 */
static void on_key(bsp_btn_t btn, bsp_btn_ev_t ev, void *user)
{
    (void)user;
    /* 先过守卫再查就绪：release 可能落在“已采样、未就绪”之间，先被丢掉的话
     * 守卫就撤不了防，只能等兜底到期。 */
    const bool was_armed = s_key_guard.armed;
    if (key_guard_consume(&s_key_guard, ev == BSP_BTN_RELEASE, esp_timer_get_time())) {
        if (was_armed && !s_key_guard.armed) {
            ESP_LOGI(TAG, "启动按键已松手，按键恢复响应");
        }
        return;
    }
    if (!s_input_ready) {
        return;
    }
    if (ev == BSP_BTN_CLICK || ev == BSP_BTN_LONG) {
        totp_app_on_key((int)btn, (int)ev);
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "暮光令牌启动");

    /* 先武装按键守卫：若开机时有键按着，动作吞到松手为止（见 on_key）。 */
    key_guard_arm(&s_key_guard, esp_timer_get_time(), KEY_GUARD_MAX_US);

    bsp_i2c_init();

    if (store_init() != ESP_OK) {
        ESP_LOGE(TAG, "NVS 初始化失败，账号与 Wi-Fi 都无法保存");
    }

    if (bsp_display_init() != ESP_OK || bsp_lvgl_init() == NULL) {
        ESP_LOGE(TAG, "显示/LVGL 初始化失败(MOSI=%d SCLK=%d CS=%d DC=%d BL=%d)", BSP_LCD_MOSI,
                 BSP_LCD_SCLK, BSP_LCD_CS, BSP_LCD_DC, BSP_LCD_BL);
        return;
    }
    bsp_display_backlight(90);

    if (bsp_battery_init() != ESP_OK) {
        ESP_LOGW(TAG, "电量计初始化失败，界面不显示电量");
    }
    if (bsp_button_init(on_key, NULL) != ESP_OK) {
        ESP_LOGE(TAG, "按键初始化失败");
    } else if (s_key_guard.armed) {
        /* 若启动键在按键驱动启动前就已松手，组件不会产生 release 事件，守卫会
         * 一直拦到兜底。初始化完成后按真实电压同步一次：已松手立即撤防。 */
        const bool released = bsp_button_read_mv() >= BSP_BTN_MV_RELEASED_MIN;
        key_guard_sync_released(&s_key_guard, released);
        if (!s_key_guard.armed) {
            ESP_LOGI(TAG, "启动键在按键驱动启动前已松手，提前撤防");
        }
    }

    if (bsp_lvgl_lock(1000)) {
        totp_app_create();
        bsp_lvgl_unlock();
        s_input_ready = true;
    }

    totp_console_start();
    totp_net_start();

    ESP_LOGI(TAG, "就绪：%d 个账号", store_count());
}
