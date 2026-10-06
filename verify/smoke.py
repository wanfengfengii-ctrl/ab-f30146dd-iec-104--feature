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


def rc_i(send: int, recv: int, cot: int, *, direction="client",
         coa=1, ioa=10, scs=1, qoc=0x80, pn=False) -> str:
    """携带 Type 45 C_SC_NA_1 单对象遥控 ASDU 的 I 帧（无时间戳版本见带 ts 包装）。"""
    cot_low = cot | (0x40 if pn else 0)
    asdu = bytes([
        45, 1, cot_low, 0,
        coa & 0xFF, (coa >> 8) & 0xFF,
        ioa & 0xFF, (ioa >> 8) & 0xFF, (ioa >> 16) & 0xFF,
        scs, qoc,
    ])
    body = bytes([
        (send << 1) & 0xFF, (send << 1) >> 8,
        (recv << 1) & 0xFF, (recv << 1) >> 8,
    ]) + asdu
    return (bytes([0x68, len(body)]) + body).hex()


def rc_frame(send, recv, cot, *, ts, direction="client", **kw):
    frame = {"direction": direction, "apdu": rc_i(send, recv, cot,
                                                  direction=direction, **kw)}
    if ts is not None:
        frame["capturedAtUs"] = ts
    return frame


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

    # 5. 旧会话回归：省略 remoteControl 时成功结果不含 completed/rejected
    status, data = post(legal)
    result = data.get("result", {})
    check("省略 remoteControl 时保留原结果字段（无 completed/rejected）",
          status == 200 and "completed" not in result and "rejected" not in result,
          str(result))

    # 6. 合法遥控：两个不同信息对象的 Type 45 选择/执行/终止链路交错完成
    rc_legal = {
        "maxWindow": 16,
        "remoteControl": {"maxSelectDelayUs": 100000},
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 0},
            {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 0},
            rc_frame(0, 0, 6, ioa=10, qoc=0x80, ts=100),
            rc_frame(1, 0, 6, ioa=20, qoc=0x80, ts=101),
            rc_frame(0, 2, 7, ioa=10, qoc=0x80, ts=102, direction="server"),
            rc_frame(1, 2, 7, ioa=20, qoc=0x80, ts=103, direction="server"),
            rc_frame(2, 1, 6, ioa=10, qoc=0x00, ts=110),
            rc_frame(3, 1, 6, ioa=20, qoc=0x00, ts=111),
            rc_frame(2, 4, 7, ioa=10, qoc=0x00, ts=120, direction="server"),
            rc_frame(3, 4, 7, ioa=20, qoc=0x00, ts=121, direction="server"),
            rc_frame(4, 4, 10, ioa=10, qoc=0x00, ts=130, direction="server"),
            rc_frame(5, 4, 10, ioa=20, qoc=0x00, ts=131, direction="server"),
        ],
    }
    status, data = post(rc_legal)
    result = data.get("result", {})
    check("合法交错遥控链路返回 200", status == 200, f"{status} {data}")
    check("两条遥控链路均 completed",
          result.get("completed") == 2 and result.get("rejected") == 0,
          str(result.get("completed")) + "/" + str(result.get("rejected")))

    # 7. 负确认：选择否定确认结束操作并计为 rejected
    rc_rejected = {
        "maxWindow": 16,
        "remoteControl": {"maxSelectDelayUs": 100000},
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 0},
            {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 0},
            rc_frame(0, 0, 6, ioa=10, qoc=0x80, ts=100),
            rc_frame(0, 1, 7, ioa=10, qoc=0x80, pn=True, ts=110,
                     direction="server"),
        ],
    }
    status, data = post(rc_rejected)
    result = data.get("result", {})
    check("选择负确认返回 200 且计为 rejected",
          status == 200 and result.get("rejected") == 1
          and result.get("completed") == 0,
          f"{status} {result}")

    # 8. 非法遥控链路：控制域合法但执行激活缺少选择证据
    rc_no_select = {
        "maxWindow": 16,
        "remoteControl": {"maxSelectDelayUs": 100000},
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 0},
            {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 0},
            rc_frame(0, 0, 6, ioa=10, qoc=0x00, ts=100),  # 直接执行
        ],
    }
    status, data = post(rc_no_select)
    err = data.get("error", {})
    check("无选择证据的执行返回 REMOTE_CONTROL_MISMATCH",
          status == 422 and err.get("code") == "REMOTE_CONTROL_MISMATCH"
          and err.get("frameIndex") == 2,
          f"{status} {err}")

    # 9. 非法遥控链路：选择/执行/确认齐全但会话结束仍缺激活终止
    rc_no_term = {
        "maxWindow": 16,
        "remoteControl": {"maxSelectDelayUs": 100000},
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 0},
            {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 0},
            rc_frame(0, 0, 6, ioa=10, qoc=0x80, ts=100),
            rc_frame(0, 1, 7, ioa=10, qoc=0x80, ts=110, direction="server"),
            rc_frame(1, 1, 6, ioa=10, qoc=0x00, ts=120),
            rc_frame(1, 2, 7, ioa=10, qoc=0x00, ts=130, direction="server"),
        ],
    }
    status, data = post(rc_no_term)
    err = data.get("error", {})
    check("缺激活终止返回 REMOTE_CONTROL_UNTERMINATED 且定位选择帧",
          status == 422 and err.get("code") == "REMOTE_CONTROL_UNTERMINATED"
          and err.get("frameIndex") == 2,
          f"{status} {err}")

    # 10. 非法遥控链路：选择正确认后超过时限才执行
    rc_timeout = {
        "maxWindow": 16,
        "remoteControl": {"maxSelectDelayUs": 1000},
        "frames": [
            {"direction": "client", "apdu": STARTDT_ACT, "capturedAtUs": 0},
            {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 0},
            rc_frame(0, 0, 6, ioa=10, qoc=0x80, ts=100),
            rc_frame(0, 1, 7, ioa=10, qoc=0x80, ts=110, direction="server"),
            rc_frame(1, 1, 6, ioa=10, qoc=0x00, ts=2000),
        ],
    }
    status, data = post(rc_timeout)
    err = data.get("error", {})
    check("超时限执行返回 REMOTE_CONTROL_TIMEOUT 且定位选择帧",
          status == 422 and err.get("code") == "REMOTE_CONTROL_TIMEOUT"
          and err.get("frameIndex") == 2,
          f"{status} {err}")

    # 11. 参数边界：maxSelectDelayUs 越界返回 INVALID_REQUEST
    for bad_delay in (0, 60_000_001):
        status, data = post({
            "maxWindow": 16,
            "remoteControl": {"maxSelectDelayUs": bad_delay},
            "frames": [
                {"direction": "client", "apdu": STARTDT_ACT},
                {"direction": "server", "apdu": STARTDT_CON},
            ],
        })
        err = data.get("error", {})
        check(f"maxSelectDelayUs={bad_delay} 返回 INVALID_REQUEST/400",
              status == 400 and err.get("code") == "INVALID_REQUEST",
              f"{status} {err}")

    print("全部冒烟通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
