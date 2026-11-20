# 暮光令牌 · FoloToy AI Passport TOTP 硬件验证器

把 AI Passport（ESP32-C3 / 8MB / ST7789P3 240×320）做成离线的两步验证（TOTP）令牌。
密钥只存在设备 NVS 里，验证码在本机计算，不经过任何服务器。

## 功能

| 功能 | 说明 |
|---|---|
| 主界面 | 大号 6/8 位验证码 + 倒计时进度条 + 账号名 + 32×32 图标 + 电量 |
| 按键 | 上/下切账号，OK 短按隐藏/显示，OK 长按重新校时 |
| 授时 | Wi-Fi + SNTP（ntp.aliyun.com / cn.pool.ntp.org），也可串口 `time <epoch>` |
| 局域网后台 | 浏览器打开 `http://<设备IP>/`，可增删改账号、上传图标、扫描配网 |
| 配网 | 没 Wi-Fi 时自动开热点 `TOTP-XXXX`（密码 8 位数字，显示在屏幕），手机连上自动弹配置页 |
| 串口 | USB 控制台：`addurl` / `add` / `list` / `del` / `time` / `wifi` / `wifi-clear` / `ap` / `reboot` |

## 快速开始

1. 烧录 `build/FoloToy-AI-Passport-full.bin` 到 `0x0`（合并镜像，含分区表）
2. 首次开机没有 Wi-Fi → 屏幕显示热点名/密码/网址
3. 手机连热点 → 自动弹出配置页（不弹就手动开 `http://192.168.4.1`）
4. 扫描选家里 Wi-Fi、填密码 → 保存，设备 20 秒内连上并切到正常模式
5. 浏览器访问设备 IP → 「账号」区块添加：名字 + Base32 密钥 +（可选）图标

## 局域网后台接口

```
GET    /                     单页后台（内嵌在固件里，离线可用）
GET    /api/status           {ip, accounts, time_ok, uptime, ap}
GET    /api/accounts         [{index, name, digits, period, algo, has_icon, code}]
POST   /api/accounts         {name, secret, digits?, period?, algo?, icon_b64?}
PUT    /api/accounts/{i}     局部更新；icon_b64 非空=换图标，""=清除
DELETE /api/accounts/{i}
POST   /api/time             {epoch}
GET    /api/wifi/scan        [{ssid, rssi, auth}]
POST   /api/wifi             AP 模式：{ssid, password} 试连成功后关热点切 STA
```

- `icon_b64`：32×32 RGB565 小端 2048 字节的 base64（浏览器 canvas 缩放生成，设备不做图片解码）
- 请求体上限 16 KB；错误返回 `{"ok":false,"error":"..."}`

## 分区布局

```
0x000000  bootloader
0x008000  分区表
0x009000  nvs        256 KB   ← 账号、图标、Wi-Fi 凭据
0x049000  phy_init     4 KB
0x050000  factory      3.6 MB ← 应用
```

## 构建

```bash
# 环境（Hermes 的 shell 带 VIRTUAL_ENV 时必须清掉，否则 IDF 拒绝创建 venv）
env -u VIRTUAL_ENV -u PYTHONPATH -u PYTHONHOME \
  PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  IDF_PATH=~/esp-idf bash -c 'source $IDF_PATH/export.sh >/dev/null && idf.py build'

./tools/validate.sh        # 仓库门禁：仓库检查 + 主机单测（+ --firmware 连固件）
```

## 踩过的坑

1. **事件回调里不能打日志**：`sys_evt` 任务栈默认 2304 字节，`ESP_LOGI`→`vfprintf`
   会直接 stack protection fault → boot loop。重活（启动 HTTP/SNTP/AP）必须投递到
   独立任务；同时把 `CONFIG_ESP_SYSTEM_EVENT_TASK_STACK_SIZE` 提到 4096。
   ⚠ 改 `sdkconfig.defaults` 对**已存在的 `sdkconfig` 不生效**，要同时改 `sdkconfig`。
2. **中文豆腐块**：默认 Montserrat 无中文字形；LVGL 内置 `SOURCE_HAN_SANS_SC_16_CJK`
   只有 1456 字，覆盖不了 UI。`main/totp_cjk_16.c` 是从源码字符串 + 内置集合抽出的
   1449 字子集（思源黑体 + lv_font_conv）。**新增中文文案后必须重跑字符提取**。
3. **`main/CMakeLists.txt` 的 REQUIRES 要显式加 `mbedtls`**，否则 `mbedtls/md.h` 编不过。
4. **LVGL v9 API**：`lv_screen_active()`（不是 `lv_scr_act()`）；`lv_timer_create` 回调签名
   是 `void(*)(lv_timer_t*)`，不能强转无参函数。
5. **USB-Serial-JTAG 控制台非阻塞**：`fgets` 会把半条命令当一行，长 `otpauth://` 链接
   必被截断，必须按字节累积到 `\n`。
6. **`-Werror=format-truncation`**：`snprintf` 往定长字段写要换 `memcpy`+`strnlen`，
   三元表达式的两个格式串也会被 `-Werror=format=` 拦。
7. **串口权限**：`SUBSYSTEM=="tty", ATTRS{idVendor}=="303a", MODE="0666"` 写进 udev 规则，
   否则每次插拔都要 sudo。

## 验证状态

```
Build:        PASS（app 1.60 MB / 分区 3.6 MB，剩 57%）
Host tests:   PASS（totp_core / http_proto / ap_proto / key_guard …）
Device tests: 部分 PASS —— 串口命令、授时、LAN 后台 CRUD、图标存储、重启持久化已实测
Unverified:   手机各家 captive portal 弹页行为、AP+STA 共存长时内存余量、屏幕图标渲染观感
```
