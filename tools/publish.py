#!/usr/bin/env python3
"""把当前目录整棵树通过 GitHub Git Data API 上传（逐 blob，双通道重试）。

代理和直连都时不时抽风，所以每个请求都交替尝试、带退避重试。
用法：python3 tools/publish.py <owner/repo> <state-file>
state-file 记录已上传的 path → blob sha，中断后可续传。
"""
import base64
import json
import os
import subprocess
import sys
import time

TOKEN = os.environ.get("GH_TOKEN", "")
API = "https://api.github.com"
PROXY = "http://192.168.50.42:7893"


def request(method, path, payload=None, attempts=10):
    body = json.dumps(payload) if payload is not None else None
    last = ""
    for attempt in range(1, attempts + 1):
        use_proxy = attempt % 2 == 1          # 奇数次走代理，偶数次直连
        cmd = ["curl", "-sS", "--max-time", "150"]
        if use_proxy:
            cmd += ["-x", PROXY]
        cmd += ["-X", method, API + path,
                "-H", "Authorization: Bearer " + TOKEN,
                "-H", "Accept: application/vnd.github+json"]
        if body is not None:
            cmd += ["-H", "Content-Type: application/json", "--data-binary", "@-"]
        proc = subprocess.run(cmd, input=body, capture_output=True, text=True)
        out = proc.stdout.strip()
        if out.startswith("{"):
            data = json.loads(out)
            if isinstance(data, dict) and data.get("message") and "sha" not in data:
                last = data.get("message", "")[:120]
                if "rate limit" in last.lower():
                    time.sleep(30)
                    continue
            else:
                return data
        else:
            last = (proc.stderr or out or "空响应")[:120].replace("\n", " ")
        time.sleep(min(1.5 * attempt, 8))
    raise RuntimeError("%s %s 连续失败: %s" % (method, path, last))


def main():
    repo = sys.argv[1]
    state_path = sys.argv[2]
    state = {}
    if os.path.exists(state_path):
        state = json.load(open(state_path))

    files = []
    for root, dirs, names in os.walk("."):
        dirs[:] = [d for d in dirs if d not in (".git",)]
        for name in names:
            files.append(os.path.join(root, name)[2:])
    files.sort()
    print("共 %d 个文件，已上传 %d" % (len(files), len(state)), flush=True)

    for index, path in enumerate(files, 1):
        if path in state:
            continue
        content = open(path, "rb").read()
        blob = request("POST", "/repos/%s/git/blobs" % repo,
                       {"content": base64.b64encode(content).decode(), "encoding": "base64"})
        state[path] = blob["sha"]
        if index % 10 == 0 or index == len(files):
            json.dump(state, open(state_path, "w"))
            print("  %d/%d  %s" % (index, len(files), path), flush=True)
    json.dump(state, open(state_path, "w"))

    entries = [{"path": p, "mode": "100644", "type": "blob", "sha": sha} for p, sha in state.items()]
    tree = request("POST", "/repos/%s/git/trees" % repo, {"tree": entries})
    print("tree:", tree["sha"], flush=True)

    message = """暮光令牌：FoloToy AI Passport 上的 TOTP 硬件验证器

- 深色主屏：大号验证码 + 倒计时 + 32×32 账号图标 + 电量（自有 UI，非 demo 外壳）
- NVS 存密钥/图标/Wi-Fi，分区扩到 256KB（16 账号 × 2KB 图标）
- 局域网后台：账号 CRUD、RGB565 图标上传、Wi-Fi 扫描配网
- SoftAP 配网：TOTP-XXXX 热点 + captive portal（DNS 劫持 + 9 条探测路径 302）
- 中文子集字体 1449 字（思源黑体 + lv_font_conv），附 tools/gen_font.sh
- 修复 sys_evt 栈溢出：重活移出事件回调，EVENT_TASK_STACK_SIZE 2304→4096
- 基于 FoloToy/ai-passport（MIT）的 BSP 驱动层"""

    commit = request("POST", "/repos/%s/git/commits" % repo, {"message": message, "tree": tree["sha"]})
    print("commit:", commit["sha"], flush=True)

    try:
        ref = request("POST", "/repos/%s/git/refs" % repo,
                      {"ref": "refs/heads/main", "sha": commit["sha"]})
    except RuntimeError:
        ref = request("PATCH", "/repos/%s/git/refs/heads/main" % repo,
                      {"sha": commit["sha"], "force": True})
    print("ref:", ref.get("ref"), "→", ref.get("object", {}).get("sha"), flush=True)


if __name__ == "__main__":
    main()
