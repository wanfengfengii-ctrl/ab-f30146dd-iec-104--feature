"""对运行中的服务执行合法/非法会话冒烟。

由 verify.sh 在一次性容器中调用，通过 HTTP 访问 API_URL。
任一断言失败即以非零退出码结束，并打印差异。
"""

import json
import os
import sys
import urllib.error
import urllib.request

API_URL = os.environ.get("API_URL", "http://api:8080").rstrip("/")
AUDIT_URL = API_URL + "/api/iec104/sessions/audit"


def i_frame(send: int, recv: int = 0) -> str:
    body = bytes(
        [(send << 1) & 0xFF, (send << 1) >> 8,
         (recv << 1) & 0xFF, (recv << 1) >> 8,
         0x01, 0x04, 0x03, 0x00, 0x00, 0x00]
    )
    return (bytes([0x68, len(body)]) + body).hex()


def s_frame(recv: int) -> str:
    body = bytes([0x01, 0x00, (recv << 1) & 0xFF, (recv << 1) >> 8])
    return (bytes([0x68, 4]) + body).hex()


def rc_asdu(cot: int, ioa: int, qos: int, ca: int = 1, pn: bool = False) -> bytes:
    """C_SC_NA_1（Type 45）单对象 ASDU。"""
    return bytes(
        [
            45,
            0x01,
            (cot & 0x3F) | (0x40 if pn else 0),
            0x00,
            ca & 0xFF,
            ca >> 8,
            ioa & 0xFF,
            (ioa >> 8) & 0xFF,
            (ioa >> 16) & 0xFF,
            qos,
        ]
    )


def rc_frame(send: int, recv: int, cot: int, ioa: int, qos: int,
             pn: bool = False, ca: int = 1) -> str:
    """携带 C_SC_NA_1（Type 45）单对象 ASDU 的 I 帧。"""
    return (
        bytes([0x68, 4 + 10])
        + bytes(
            [(send << 1) & 0xFF, (send << 1) >> 8,
             (recv << 1) & 0xFF, (recv << 1) >> 8]
        )
        + rc_asdu(cot, ioa, qos, ca, pn)
    ).hex()


STARTDT_ACT = "680407000000"
STARTDT_CON = "68040b000000"
STOPDT_ACT = "680413000000"
STOPDT_CON = "680423000000"


def post(payload):
    req = urllib.request.Request(
        AUDIT_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def check(label, condition, detail=""):
    if not condition:
        print(f"[FAIL] {label} {detail}")
        sys.exit(1)
    print(f"[PASS] {label}")


def main() -> int:
    # 0. 健康检查
    with urllib.request.urlopen(API_URL + "/health", timeout=5) as resp:
        check("健康检查 /health 返回 200", resp.status == 200)

    # 1. 合法会话：启动 -> 双向 I 帧交换并互相确认 -> 停止
    legal = {
        "maxWindow": 4,
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 1},
            {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 2},
            {"direction": "client", "apdu": i_frame(0, 0), "capturedAtUs": 3},
            {"direction": "client", "apdu": i_frame(1, 0), "capturedAtUs": 4},
            {"direction": "server", "apdu": i_frame(0, 2), "capturedAtUs": 5},
            {"direction": "client", "apdu": s_frame(1), "capturedAtUs": 6},
            {"direction": "client", "apdu": STOPDT_ACT, "capturedAtUs": 7},
            {"direction": "server", "apdu": STOPDT_CON, "capturedAtUs": 8},
        ],
    }
    status, data = post(legal)
    check("合法会话返回 200", status == 200, f"实际 {status} {data}")
    check("合法会话 ok=true", data.get("ok") is True)
    result = data["result"]
    check("按方向统计 I 帧数",
          result["iFrames"] == {"client": 2, "server": 1},
          str(result["iFrames"]))
    check("最终待确认数为 0",
          result["outstanding"] == {"client": 0, "server": 0},
          str(result["outstanding"]))
    check("STARTDT 配对计数",
          result["handshakes"]["STARTDT"] == {"act": 1, "con": 1, "paired": 1},
          str(result["handshakes"]["STARTDT"]))
    check("STOPDT 配对计数",
          result["handshakes"]["STOPDT"] == {"act": 1, "con": 1, "paired": 1},
          str(result["handshakes"]["STOPDT"]))

    # 2. 非法会话：未启动即发 I 帧
    illegal_phase = {
        "maxWindow": 4,
        "frames": [
            {"direction": "client", "apdu": i_frame(0, 0), "capturedAtUs": 1},
        ],
    }
    status, data = post(illegal_phase)
    check("阶段违规返回 422", status == 422, f"实际 {status}")
    err = data.get("error", {})
    check("稳定错误码 I_FRAME_OUTSIDE_PHASE",
          err.get("code") == "I_FRAME_OUTSIDE_PHASE", str(err))
    check("定位到最早受影响帧下标 0", err.get("frameIndex") == 0, str(err))
    check("说明不包含对后续裁决的引用", "后续" not in err.get("message", ""),
          err.get("message"))

    # 3. 非法会话：确认号越过对端已发送数据
    illegal_ack = {
        "maxWindow": 4,
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 1},
            {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 2},
            {"direction": "server", "apdu": s_frame(1), "capturedAtUs": 3},
        ],
    }
    status, data = post(illegal_ack)
    err = data.get("error", {})
    check("越界确认返回 422 且错误码/下标稳定",
          status == 422 and err.get("code") == "ACK_AHEAD"
          and err.get("frameIndex") == 2,
          f"{status} {err}")

    # 4. 非法 APDU：尾随字节
    illegal_apdu = {
        "maxWindow": 4,
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT + "ff",
             "capturedAtUs": 1},
        ],
    }
    status, data = post(illegal_apdu)
    err = data.get("error", {})
    check("尾随字节返回 INVALID_APDU 且下标为 0",
          status == 422 and err.get("code") == "INVALID_APDU"
          and err.get("frameIndex") == 0,
          f"{status} {err}")

    # 5. 遥控合法交错：两个不同信息对象的选择-执行-终止链交错闭合
    rc_interleave = {
        "maxWindow": 16,
        "remoteControl": {"maxSelectDelayUs": 5_000_000},
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 1},
            {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 2},
            {"direction": "client", "apdu": rc_frame(0, 0, 6, 101, 0x81),
             "capturedAtUs": 100},  # IOA=101 选择
            {"direction": "client", "apdu": rc_frame(1, 0, 6, 102, 0x81),
             "capturedAtUs": 101},  # IOA=102 选择
            {"direction": "server", "apdu": rc_frame(0, 2, 7, 101, 0x81),
             "capturedAtUs": 102},  # 101 选择确认
            {"direction": "server", "apdu": rc_frame(1, 2, 7, 102, 0x81),
             "capturedAtUs": 103},  # 102 选择确认
            {"direction": "client", "apdu": rc_frame(2, 2, 6, 101, 0x01),
             "capturedAtUs": 104},  # 101 执行
            {"direction": "server", "apdu": rc_frame(2, 3, 7, 101, 0x01),
             "capturedAtUs": 105},  # 101 执行确认
            {"direction": "server", "apdu": rc_frame(3, 3, 10, 101, 0x01),
             "capturedAtUs": 106},  # 101 终止
            {"direction": "client", "apdu": rc_frame(3, 4, 6, 102, 0x01),
             "capturedAtUs": 107},  # 102 执行
            {"direction": "server", "apdu": rc_frame(4, 4, 7, 102, 0x01),
             "capturedAtUs": 108},  # 102 执行确认
            {"direction": "server", "apdu": rc_frame(5, 4, 10, 102, 0x01),
             "capturedAtUs": 109},  # 102 终止
            {"direction": "client", "apdu": s_frame(6), "capturedAtUs": 110},
        ],
    }
    status, data = post(rc_interleave)
    rc = data.get("result", {}).get("remoteControl") if status == 200 else None
    check("合法交错遥控链返回 200 且 completed=2",
          status == 200 and rc == {"completed": 2, "rejected": 0},
          f"{status} {data}")

    # 6. 遥控负确认：选择被子站拒绝，操作计 rejected，审计仍通过
    rc_negative = {
        "maxWindow": 16,
        "remoteControl": {"maxSelectDelayUs": 5_000_000},
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 1},
            {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 2},
            {"direction": "client", "apdu": rc_frame(0, 0, 6, 101, 0x81),
             "capturedAtUs": 100},
            {"direction": "server", "apdu": rc_frame(0, 1, 7, 101, 0x81, pn=True),
             "capturedAtUs": 101},  # P/N=1 选择负确认
        ],
    }
    status, data = post(rc_negative)
    rc = data.get("result", {}).get("remoteControl") if status == 200 else None
    check("选择负确认计 rejected 且审计通过",
          status == 200 and rc == {"completed": 0, "rejected": 1},
          f"{status} {data}")

    # 7. 非法遥控链路：控制域/序号完全合法，但缺少正确的选择与终止证据
    illegal_rc_frames = [
        {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 1},
        {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 2},
        # 未先选择即直接执行（QOS SE=0）
        {"direction": "client", "apdu": rc_frame(0, 0, 6, 101, 0x01),
         "capturedAtUs": 100},
    ]
    illegal_rc = {
        "maxWindow": 16,
        "remoteControl": {"maxSelectDelayUs": 5_000_000},
        "frames": illegal_rc_frames,
    }
    status, data = post(illegal_rc)
    err = data.get("error", {})
    check("缺少选择证据的遥控记录被拒绝（稳定错误码 + 最早下标 2）",
          status == 422 and err.get("code") == "REMOTE_CONTROL_REJECTED"
          and err.get("frameIndex") == 2,
          f"{status} {err}")

    # 7b. 选择与确认齐全但缺少激活终止，会话结束仍悬挂 -> 定位最早的选择帧
    missing_term = {
        "maxWindow": 16,
        "remoteControl": {"maxSelectDelayUs": 5_000_000},
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 1},
            {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 2},
            {"direction": "client", "apdu": rc_frame(0, 0, 6, 101, 0x81),
             "capturedAtUs": 100},
            {"direction": "server", "apdu": rc_frame(0, 1, 7, 101, 0x81),
             "capturedAtUs": 101},
            {"direction": "client", "apdu": rc_frame(1, 1, 6, 101, 0x01),
             "capturedAtUs": 102},
            {"direction": "server", "apdu": rc_frame(1, 2, 7, 101, 0x01),
             "capturedAtUs": 103},
        ],
    }
    status, data = post(missing_term)
    err = data.get("error", {})
    check("缺少终止证据的遥控记录被拒绝（定位选择帧下标 2）",
          status == 422 and err.get("code") == "REMOTE_CONTROL_REJECTED"
          and err.get("frameIndex") == 2,
          f"{status} {err}")

    # 8. 省略 remoteControl 时原契约不变：结果中不含遥控裁决字段
    status, data = post(legal)
    check("省略 remoteControl 时结果保持原契约",
          status == 200 and "remoteControl" not in data.get("result", {}),
          str(data.get("result")))

    print("全部冒烟通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
