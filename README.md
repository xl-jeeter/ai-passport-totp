# 暮光令牌 · TOTP 硬件验证器（FoloToy AI Passport）

把 [FoloToy AI Passport](https://github.com/FoloToy/ai-passport)（ESP32-C3 / 8MB Flash / 无 PSRAM /
ST7789P3 240×320 / 三键）改造成一台**离线的两步验证（TOTP）令牌**。

密钥只存在设备 NVS 里，验证码在芯片上计算，不经过任何服务器。

> 本项目是 [FoloToy/ai-passport](https://github.com/FoloToy/ai-passport)（MIT）的衍生应用，
> 复用了它的 BSP 驱动层（屏幕 / 按键 / 电量 / 音频），应用层与界面全部重写。

## 功能

| | |
|---|---|
| **主界面** | 大号 6/8 位验证码 + 倒计时进度条 + 账号名 + 32×32 图标 + 电量 |
| **按键** | 上/下切换账号，OK 短按隐藏/显示，OK 长按重新校时 |
| **授时** | Wi-Fi + SNTP（ntp.aliyun.com / cn.pool.ntp.org），也可串口 `time <epoch>` |
| **局域网后台** | 浏览器打开 `http://<设备IP>/`，增删改账号、上传图标、扫描配网 |
| **SoftAP 配网** | 没 Wi-Fi 时自动开热点 `TOTP-XXXX`，手机连上自动弹配置页（captive portal） |
| **串口控制台** | `addurl` / `add` / `list` / `del` / `time` / `wifi` / `wifi-clear` / `ap` / `reboot` |

## 快速开始

```bash
# 1. 构建（ESP-IDF 5.4.2 或 5.5.x）
idf.py set-target esp32c3
idf.py build

# 2. 烧录合并镜像（会重置分区表，NVS 一并清空）
esptool --chip esp32c3 -p /dev/ttyACM0 -b 460800 \
  --before default_reset --after hard_reset write_flash \
  --flash_mode dio --flash_freq 80m --flash_size 8MB \
  0x0 build/FoloToy-AI-Passport-full.bin
```

首次开机没有 Wi-Fi：

1. 屏幕显示热点名 / 密码 / 网址
2. 手机连 `TOTP-XXXX`（密码 8 位数字，从 MAC 派生）→ 自动弹配置页
3. 选家里 Wi-Fi、填密码、保存 → 20 秒内连上并切到正常模式
4. 浏览器访问设备 IP → 添加账号：名字 + Base32 密钥 +（可选）图标

## 局域网后台接口

```text
GET    /                     单页后台（内嵌固件，离线可用）
GET    /api/status           {ip, accounts, time_ok, uptime, ap}
GET    /api/accounts         [{index, name, digits, period, algo, has_icon, code}]
POST   /api/accounts         {name, secret, digits?, period?, algo?, icon_b64?}
PUT    /api/accounts/{i}     局部更新；icon_b64 非空=换图标，""=清除
DELETE /api/accounts/{i}
POST   /api/time             {epoch}
GET    /api/wifi/scan        [{ssid, rssi, auth}]
POST   /api/wifi             AP 模式：{ssid, password} 试连成功后关热点切 STA
```

`icon_b64` = 32×32 RGB565 小端 2048 字节的 base64（浏览器 canvas 缩放生成，设备不做图片解码）。
请求体上限 16 KB，错误返回 `{"ok":false,"error":"..."}`。

## 分区布局

```text
0x000000  bootloader
0x008000  分区表
0x009000  nvs        256 KB   ← 账号、图标、Wi-Fi 凭据
0x049000  phy_init     4 KB
0x050000  factory      3.6 MB ← 应用（约 1.6 MB）
```

> 相比上游默认分区，NVS 从 24 KB 扩到 256 KB —— 每个图标占 2 KB，16 个账号需要空间。

## 中文显示

LVGL 内置的 `SOURCE_HAN_SANS_SC_16_CJK` 只有 1456 字，覆盖不了 UI 文案。
`main/totp_cjk_16.c` 是**按源码实际用字生成的子集**（1449 字）：

```bash
# 需要：pip install fonttools；npm i -g lv_font_conv
./tools/gen_font.sh          # 改完中文文案后重跑，再重新编译
```

字体子集不覆盖的汉字会显示成方框（tofu）。新增文案后忘了重跑脚本是最常见的坑。

## 踩过的坑

1. **事件回调里不能打日志**：`sys_evt` 任务栈默认只有 2304 字节，`ESP_LOGI` → `vfprintf`
   会直接 stack protection fault → boot loop。重活（启动 HTTP / SNTP / AP）必须投递到独立任务，
   回调里只 `xEventGroupSetBits`。
2. **`sdkconfig.defaults` 对已存在的 `sdkconfig` 不生效**。改配置要两边都改，否则
   看起来改了其实没生效（本项目踩过两次：事件栈 4096、HTTPD 头长度 2048）。
3. **`main/CMakeLists.txt` 的 REQUIRES 要显式加 `mbedtls`**，否则 `mbedtls/md.h` 编不过。
4. **LVGL v9 API**：`lv_screen_active()`（不是 `lv_scr_act()`）；`lv_timer_create` 回调签名是
   `void(*)(lv_timer_t*)`，不能把无参函数强转进去。
5. **USB-Serial-JTAG 控制台是非阻塞的**：`fgets` 会把半条命令当一行返回，长
   `otpauth://` 链接必被截断，必须按字节累积到 `\n`。
6. **`-Werror=format-truncation`**：`snprintf` 往定长字段写要用 `memcpy` + `strnlen`；
   三元表达式两个分支格式串不同也会被 `-Werror=format=` 拦。
7. **串口权限**：加 udev 规则 `SUBSYSTEM=="tty", ATTRS{idVendor}=="303a", MODE="0666"`，
   否则每次插拔都要 sudo。

## 验证状态

```text
Build:        PASS（app 1.60 MB / 分区 3.6 MB，剩 57%）
Host tests:   PASS（totp_core / http_proto / ap_proto / key_guard / BSP 故障注入）
Device tests: 串口命令、授时、局域网后台 CRUD、图标存储、重启持久化 —— 已实测
Unverified:   手机各家 captive portal 弹页行为、AP+STA 长期共存内存余量、屏幕图标观感
```

## 许可

上游 [FoloToy/ai-passport](https://github.com/FoloToy/ai-passport) 为 MIT，本衍生应用同样遵循 MIT，
见 [LICENSE](LICENSE)。
