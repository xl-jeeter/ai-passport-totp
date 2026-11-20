#pragma once

/* 启动局域网 HTTP 后台（80 端口）：单页网页 + REST 接口。
 * 在拿到 IP 后调用（totp_net 的 GOT_IP 回调）；可重复调用，只启动一次。
 * 所有写操作完成后会调用 totp_app_reload() 刷新界面。 */
void totp_http_start(void);
