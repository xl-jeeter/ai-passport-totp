#!/usr/bin/env bash
# 重新生成中文子集字体 main/totp_cjk_16.c
#
# 依赖：
#   npm i -g lv_font_conv
#   字体源：思源黑体 SourceHanSansSC-Regular.otf 放到 fonts/
#
# 触发时机：**任何** main/*.c、main/*.h 里新增或修改中文文案之后。
# 不重跑就会出现方框（tofu），因为字体是按源码实际用字裁剪出来的子集。
set -euo pipefail
cd "$(dirname "$0")/.."

FONT="${FONT:-fonts/SourceHanSansSC-Regular.otf}"
[ -f "$FONT" ] || { echo "缺少字体文件：$FONT"; exit 1; }
command -v lv_font_conv >/dev/null || { echo "缺少 lv_font_conv：npm i -g lv_font_conv"; exit 1; }

SYMBOLS=$(python3 - <<'PY'
import glob, re

chars = set()
for path in glob.glob('main/*.c') + glob.glob('main/*.h'):
    text = open(path, encoding='utf-8', errors='ignore').read()
    for literal in re.findall(r'"((?:[^"\\]|\\.)*)"', text):
        chars |= {ch for ch in literal if ord(ch) > 127}

# 并入 LVGL 内置 CJK 子集，覆盖常见账号名用字
src_path = 'managed_components/lvgl__lvgl/src/font/lv_font_source_han_sans_sc_16_cjk.c'
try:
    src = open(src_path, encoding='utf-8', errors='ignore').read()

    def parse_list(name):
        m = re.search(r'static const uint16_t %s\[\] = \{(.*?)\};' % name, src, re.S)
        return [int(x, 0) for x in re.findall(r'0x[0-9a-fA-F]+|\d+', m.group(1))] if m else []

    covered = set(range(32, 127))
    covered |= {12289 + v for v in parse_list('unicode_list_1')}
    covered |= set(range(12362, 12362 + 24)) | set(range(12387, 12387 + 43)) | set(range(12431, 12431 + 95))
    covered |= {12527 + v for v in parse_list('unicode_list_5')}
    chars |= {chr(cp) for cp in covered if cp > 127}
except OSError:
    pass

chars |= set("·：，。！？（）【】《》、；—“”‘’…￥℃°/")
print("".join(sorted(chars)))
PY
)

echo "字符数：$(printf '%s' "$SYMBOLS" | wc -m)"

lv_font_conv --font "$FONT" \
  --range 0x20-0x7E --symbols "$SYMBOLS" \
  --size 16 --bpp 4 --format lvgl --no-compress \
  --lv-font-name totp_cjk_16 --lv-include lvgl.h \
  --output main/totp_cjk_16.c

echo "已生成 main/totp_cjk_16.c，记得重新 idf.py build"
