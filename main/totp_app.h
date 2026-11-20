#pragma once

#include "lvgl.h"

/* 创建 TOTP 主界面。必须在 bsp_lvgl_lock() 保护下调用。 */
void totp_app_create(void);

/* 由按键回调（非 LVGL 上下文）投递的事件。 */
void totp_app_on_key(int button, int event);

/* 周期刷新回调：更新验证码与倒计时，由 LVGL 定时器调用。 */
void totp_app_tick(void);

/* 账号或图标变化（串口/网页新增、修改、删除）后让界面重新读一遍。 */
void totp_app_reload(void);

/* 授时成功后刷新界面提示。 */
void totp_app_time_synced(void);
