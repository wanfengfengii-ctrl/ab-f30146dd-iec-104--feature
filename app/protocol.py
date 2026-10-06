"""IEC 60870-5-104 会话状态机与 APDU 解析。

只依赖 Python 标准库。任何违规都抛出 :class:`AuditError`，携带稳定错误码、
最早受影响帧下标（0 起）与仅针对该帧本身的说明（不引用对后续帧的裁决）。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

START_BYTE = 0x68
MIN_APDU_LEN = 6  # 起始符(1) + 长度(1) + 控制域(4)
MAX_LENGTH_FIELD = 253  # 长度字段 = 控制域(4) + ASDU(<=249)
MAX_FRAMES = 5000
MIN_WINDOW = 1
MAX_WINDOW = 16383

# 遥控（Type 45 C_SC_NA_1，单对象）相关常量。
RC_TYPE_ID = 45
RC_ASDU_LEN = 11  # 类型(1)+VSQ(1)+传送原因(2)+公共地址(2)+IOA(3)+SCS(1)+QOC(1)
RC_VSQ_SINGLE = 0x01
COT_ACTIVATION = 6
COT_ACTIVATION_CON = 7
COT_ACTIVATION_TERM = 10
RC_PN_BIT = 0x40  # 传送原因第 1 字节 bit6：P/N（0=正确认，1=负确认）
MIN_SELECT_DELAY_US = 1
MAX_SELECT_DELAY_US = 60_000_000

CLIENT = "client"
SERVER = "server"
DIRECTIONS = (CLIENT, SERVER)

_DIRECTION_ALIASES = {
    "client": CLIENT,
    "c": CLIENT,
    "master": CLIENT,
    "primary": CLIENT,
    "server": SERVER,
    "s": SERVER,
    "slave": SERVER,
    "secondary": SERVER,
    "controlled": SERVER,
}


class ErrorCode(str, Enum):
    """对外稳定错误码，取值不得随实现随意改动。"""

    INVALID_REQUEST = "INVALID_REQUEST"
    INVALID_APDU = "INVALID_APDU"
    INVALID_CONTROL_FIELD = "INVALID_CONTROL_FIELD"
    FRAMES_NOT_ORDERED = "FRAMES_NOT_ORDERED"
    SEND_SEQUENCE_INVALID = "SEND_SEQUENCE_INVALID"
    ACK_BACKWARDS = "ACK_BACKWARDS"
    ACK_AHEAD = "ACK_AHEAD"
    WINDOW_EXCEEDED = "WINDOW_EXCEEDED"
    HANDSHAKE_UNMATCHED = "HANDSHAKE_UNMATCHED"
    HANDSHAKE_OVERLAP = "HANDSHAKE_OVERLAP"
    I_FRAME_OUTSIDE_PHASE = "I_FRAME_OUTSIDE_PHASE"
    REMOTE_CONTROL_INVALID = "REMOTE_CONTROL_INVALID"
    REMOTE_CONTROL_MISMATCH = "REMOTE_CONTROL_MISMATCH"
    REMOTE_CONTROL_REENTRY = "REMOTE_CONTROL_REENTRY"
    REMOTE_CONTROL_TIMEOUT = "REMOTE_CONTROL_TIMEOUT"
    REMOTE_CONTROL_UNTERMINATED = "REMOTE_CONTROL_UNTERMINATED"


# 请求结构问题属于 400；其余为可定位到帧的协议违规，属于 422。
_HTTP_STATUS = {
    ErrorCode.INVALID_REQUEST: 400,
    ErrorCode.INVALID_APDU: 422,
    ErrorCode.INVALID_CONTROL_FIELD: 422,
    ErrorCode.FRAMES_NOT_ORDERED: 422,
    ErrorCode.SEND_SEQUENCE_INVALID: 422,
    ErrorCode.ACK_BACKWARDS: 422,
    ErrorCode.ACK_AHEAD: 422,
    ErrorCode.WINDOW_EXCEEDED: 422,
    ErrorCode.HANDSHAKE_UNMATCHED: 422,
    ErrorCode.HANDSHAKE_OVERLAP: 422,
    ErrorCode.I_FRAME_OUTSIDE_PHASE: 422,
    ErrorCode.REMOTE_CONTROL_INVALID: 422,
    ErrorCode.REMOTE_CONTROL_MISMATCH: 422,
    ErrorCode.REMOTE_CONTROL_REENTRY: 422,
    ErrorCode.REMOTE_CONTROL_TIMEOUT: 422,
    ErrorCode.REMOTE_CONTROL_UNTERMINATED: 422,
}


def http_status_for(code: ErrorCode) -> int:
    return _HTTP_STATUS[code]


class AuditError(Exception):
    def __init__(self, code: ErrorCode, frame_index: int, message: str):
        super().__init__(message)
        self.code = code
        self.frame_index = frame_index
        self.message = message

    def to_dict(self) -> dict:
        return {
            "ok": False,
            "error": {
                "code": self.code.value,
                "frameIndex": self.frame_index,
                "message": self.message,
            },
        }


@dataclass(frozen=True)
class ParsedFrame:
    kind: str  # "I" | "S" | "U"
    send_seq: Optional[int] = None
    recv_seq: Optional[int] = None
    u_type: Optional[str] = None  # STARTDT | STOPDT | TESTFR
    u_act: Optional[bool] = None
    asdu_raw: Optional[bytes] = None  # I 帧的 ASDU 原始字节（S/U 帧为 None）


@dataclass(frozen=True)
class RemoteControlASDU:
    """Type 45 C_SC_NA_1 单对象命令 ASDU 的取证要素。"""

    coa: int        # 公共地址
    ioa: int       # 信息对象地址
    cot: int        # 传送原因：6=激活 7=激活确认 10=激活终止
    pn: bool        # 命令状态：True=负确认(P/N=1)，False=正确认/请求
    scs: int        # 单命令状态值（0/1）
    qoc: int        # 命令限定词（bit7=S/E，bit2..6=QU）


_U_FUNCTIONS = {
    0x04: ("STARTDT", True),   # 0x07
    0x08: ("STARTDT", False),  # 0x0B
    0x10: ("STOPDT", True),    # 0x13
    0x20: ("STOPDT", False),   # 0x23
    0x40: ("TESTFR", True),    # 0x43
    0x80: ("TESTFR", False),   # 0x83
}


def normalize_direction(value: object) -> Optional[str]:
    if not isinstance(value, str):
        return None
    return _DIRECTION_ALIASES.get(value.strip().lower())


def parse_apdu(raw_hex: object) -> ParsedFrame:
    """解析完整十六进制 APDU，仅接受 I/S/U 三种控制格式。

    起始符、长度、控制域必须合法，且长度字段与实际字节数严格一致
    （既不截断也无尾随字节）。
    """
    if not isinstance(raw_hex, str):
        raise AuditError(ErrorCode.INVALID_APDU, -1, "apdu 必须为十六进制字符串")
    text = "".join(raw_hex.split())
    try:
        data = bytes.fromhex(text)
    except ValueError:
        raise AuditError(
            ErrorCode.INVALID_APDU, -1, "APDU 不是合法的偶数位十六进制字符串"
        )

    if len(data) < MIN_APDU_LEN:
        raise AuditError(ErrorCode.INVALID_APDU, -1, "APDU 短于最小长度 6 字节")
    if data[0] != START_BYTE:
        raise AuditError(ErrorCode.INVALID_APDU, -1, "起始符不是 0x68")

    length = data[1]
    if length < 4:
        raise AuditError(
            ErrorCode.INVALID_APDU, -1, "长度字段小于控制域长度 4"
        )
    if length > MAX_LENGTH_FIELD:
        raise AuditError(
            ErrorCode.INVALID_APDU, -1, "长度字段超过上限 253"
        )
    # 长度只计控制域与 ASDU；整体必须恰为 2+length，拒绝截断与尾随字节。
    if len(data) != 2 + length:
        raise AuditError(
            ErrorCode.INVALID_APDU,
            -1,
            "长度字段与实际字节数不符（存在截断或尾随字节）",
        )

    b2, b3, b4, b5 = data[2], data[3], data[4], data[5]

    if b2 & 0x01 == 0x00:
        # I 格式：第 1 个八字节组最低位为 0
        send_seq = ((b3 << 8) | b2) >> 1
        recv_seq = ((b5 << 8) | b4) >> 1
        return ParsedFrame(
            kind="I",
            send_seq=send_seq,
            recv_seq=recv_seq,
            asdu_raw=bytes(data[6:]),
        )

    if b2 & 0x03 == 0x01:
        # S 格式：最低两位为 01
        if length != 4:
            raise AuditError(
                ErrorCode.INVALID_APDU,
                -1,
                "S 格式不携带 ASDU，长度字段必须恰为 4",
            )
        if b3 != 0:
            raise AuditError(
                ErrorCode.INVALID_CONTROL_FIELD,
                -1,
                "S 格式控制域的发送序号保留位非零",
            )
        recv_seq = ((b5 << 8) | b4) >> 1
        return ParsedFrame(kind="S", recv_seq=recv_seq)

    # U 格式：最低两位为 11
    if length != 4:
        raise AuditError(
            ErrorCode.INVALID_APDU,
            -1,
            "U 格式不携带 ASDU，长度字段必须恰为 4",
        )
    if b3 != 0 or b4 != 0 or b5 != 0:
        raise AuditError(
            ErrorCode.INVALID_CONTROL_FIELD,
            -1,
            "U 格式控制域的保留字节非零",
        )
    parsed = _U_FUNCTIONS.get(b2 & 0xFC)
    if parsed is None:
        raise AuditError(
            ErrorCode.INVALID_CONTROL_FIELD,
            -1,
            "U 格式功能码未知（不是 STARTDT/STOPDT/TESTFR 的 act 或 con）",
        )
    u_type, u_act = parsed
    return ParsedFrame(kind="U", u_type=u_type, u_act=u_act)


@dataclass
class _PeerState:
    next_send: int = 0  # 本端下一个应使用的 N(S)，双方均从 0 起
    last_ack: int = 0  # 本端已发布的最大 N(R)，确认号不得倒退


def _opposite(direction: str) -> str:
    return SERVER if direction == CLIENT else CLIENT


def parse_remote_control(asdu: bytes) -> RemoteControlASDU:
    """解析 Type 45 C_SC_NA_1 单对象遥控 ASDU。

    仅在启用遥控裁决且类型标识为 45 时调用。布局（11 字节）：
    类型(1) | VSQ(1) | 传送原因(2) | 公共地址(2) | 信息对象地址(3) | SCS(1) | QOC(1)。
    任何结构/字段不合法都抛 REMOTE_CONTROL_INVALID（帧下标由调用方绑定）。
    """
    if len(asdu) != RC_ASDU_LEN:
        raise AuditError(
            ErrorCode.REMOTE_CONTROL_INVALID,
            -1,
            f"Type {RC_TYPE_ID} 单对象遥控 ASDU 长度必须为 {RC_ASDU_LEN} 字节，"
            f"实际 {len(asdu)} 字节",
        )
    if asdu[1] != RC_VSQ_SINGLE:
        raise AuditError(
            ErrorCode.REMOTE_CONTROL_INVALID,
            -1,
            f"Type {RC_TYPE_ID} 遥控裁决仅支持单对象（VSQ 必须为 1），"
            f"实际 VSQ=0x{asdu[1]:02x}",
        )

    cot_low = asdu[2]
    cot_code = cot_low & 0x3F
    if cot_code not in (
        COT_ACTIVATION,
        COT_ACTIVATION_CON,
        COT_ACTIVATION_TERM,
    ):
        raise AuditError(
            ErrorCode.REMOTE_CONTROL_INVALID,
            -1,
            f"遥控原语只接受传送原因 6(激活)/7(激活确认)/10(激活终止)，"
            f"实际 {cot_code}",
        )

    # P/N 位于传送原因低字节 bit6；bit7 为 T，高字节为始发地址，均不据此拒绝。
    pn = bool(cot_low & RC_PN_BIT)
    if cot_code == COT_ACTIVATION and pn:
        raise AuditError(
            ErrorCode.REMOTE_CONTROL_INVALID,
            -1,
            "激活请求（传送原因 6）不得携带否定确认位 P/N",
        )
    if cot_code == COT_ACTIVATION_TERM and pn:
        raise AuditError(
            ErrorCode.REMOTE_CONTROL_INVALID,
            -1,
            "激活终止（传送原因 10）不得携带否定确认位 P/N",
        )

    coa = asdu[4] | (asdu[5] << 8)
    ioa = asdu[6] | (asdu[7] << 8) | (asdu[8] << 16)
    scs = asdu[9]
    qoc = asdu[10]
    if scs & 0xFE:
        raise AuditError(
            ErrorCode.REMOTE_CONTROL_INVALID,
            -1,
            f"单命令状态(SCS)保留位非零：0x{scs:02x}（仅 bit0 有效）",
        )
    if qoc & 0x03:
        raise AuditError(
            ErrorCode.REMOTE_CONTROL_INVALID,
            -1,
            f"命令限定词(QOC)低 2 位为保留位，必须为 0：0x{qoc:02x}",
        )
    return RemoteControlASDU(
        coa=coa,
        ioa=ioa,
        cot=cot_code,
        pn=pn,
        scs=scs,
        qoc=qoc,
    )


@dataclass
class _RemoteControlOp:
    """同一 (公共地址, 信息对象地址) 上一次遥控操作的裁决进度。"""

    stage: str          # SELECT_WAIT_CON | WAIT_EXECUTE | EXEC_WAIT_CON | WAIT_TERM
    select_index: int   # 选择激活帧下标（悬挂时作为最早证据）
    scs: int            # 选择/执行要求一致的单命令状态值
    select_qu: int      # 选择限定词中的 QU（bit2..6）
    select_qoc: int     # 选择激活 QOC 原文（S/E=1）
    exec_qoc: Optional[int] = None  # 执行激活 QOC 原文（S/E=0）
    select_con_ts: Optional[int] = None


def _qu_of(qoc: int) -> int:
    return (qoc >> 2) & 0x1F


def _rc_error(index: int, message: str) -> AuditError:
    return AuditError(ErrorCode.REMOTE_CONTROL_MISMATCH, index, message)


def _apply_remote_control(
    rc: RemoteControlASDU,
    direction: str,
    index: int,
    ts: Optional[int],
    ops: dict[tuple[int, int], _RemoteControlOp],
    counts: dict[str, int],
) -> None:
    """对一帧 Type 45 遥控原语执行选择/执行/终止证据链裁决。

    选择→执行超时由主循环的时间巡检统一先行判定，这里只处理阶段/方向/字段。
    """
    key = (rc.coa, rc.ioa)
    op = ops.get(key)

    if rc.cot == COT_ACTIVATION:
        # 激活只能由主站(client)发起。
        if direction != CLIENT:
            raise _rc_error(
                index,
                "遥控激活（传送原因 6）只能由主站发起，子站不得发送激活请求",
            )
        is_select = bool(rc.qoc & 0x80)
        if op is None:
            if not is_select:
                raise _rc_error(
                    index,
                    "执行激活缺少先于它的选择激活及选择正确认（QOC 的 S/E 位为执行）",
                )
            ops[key] = _RemoteControlOp(
                stage="SELECT_WAIT_CON",
                select_index=index,
                scs=rc.scs,
                select_qu=_qu_of(rc.qoc),
                select_qoc=rc.qoc,
            )
            return
        if op.stage == "WAIT_EXECUTE" and not is_select:
            # 选择正确认之后的执行激活：命令状态与限定词(QU)必须与选择对应。
            if rc.scs != op.scs:
                raise _rc_error(
                    index,
                    "执行激活的单命令状态(SCS)与选择阶段不对应",
                )
            if _qu_of(rc.qoc) != op.select_qu:
                raise _rc_error(
                    index,
                    "执行激活的命令限定词(QU)与选择阶段不对应",
                )
            op.stage = "EXEC_WAIT_CON"
            op.exec_qoc = rc.qoc
            return
        # 同一对象上一次操作尚未终结（含等待确认期间重发、等待执行期改发选择）：
        # 同一对象不得重入。
        raise AuditError(
            ErrorCode.REMOTE_CONTROL_REENTRY,
            index,
            f"公共地址 {rc.coa}、信息对象 {rc.ioa} 的上一次遥控操作尚未终结，"
            "同一对象不得重入",
        )

    if rc.cot == COT_ACTIVATION_CON:
        # 激活确认只能由子站(server)给出。
        if direction != SERVER:
            raise _rc_error(
                index,
                "遥控激活确认（传送原因 7）只能由子站给出，主站不得发送确认",
            )
        if op is None:
            raise _rc_error(
                index,
                f"公共地址 {rc.coa}、信息对象 {rc.ioa} 的激活确认没有对应的、"
                "来自主站的待确认激活",
            )
        if rc.pn:
            # 负确认只能否定当前等待确认的选择或执行；字段仍须与请求对应。
            if op.stage not in ("SELECT_WAIT_CON", "EXEC_WAIT_CON"):
                raise _rc_error(
                    index,
                    f"阶段不匹配：当前阶段 {op.stage} 不等待激活确认，"
                    "却收到否定激活确认",
                )
            expected_qoc = (
                op.select_qoc
                if op.stage == "SELECT_WAIT_CON"
                else op.exec_qoc
            )
            if rc.scs != op.scs or rc.qoc != expected_qoc:
                raise _rc_error(
                    index,
                    "否定激活确认的命令状态(SCS)或限定词(QOC)与待确认激活不对应",
                )
            # 负确认结束操作并计为 rejected。
            del ops[key]
            counts["rejected"] += 1
            return
        # 正确认
        if op.stage == "SELECT_WAIT_CON":
            if rc.scs != op.scs or rc.qoc != op.select_qoc:
                raise _rc_error(
                    index,
                    "选择激活确认的命令状态(SCS)或限定词(QOC)与选择激活不对应",
                )
            op.stage = "WAIT_EXECUTE"
            op.select_con_ts = ts
            return
        if op.stage == "EXEC_WAIT_CON":
            if rc.scs != op.scs or rc.qoc != op.exec_qoc:
                raise _rc_error(
                    index,
                    "执行激活确认的命令状态(SCS)或限定词(QOC)与执行激活不对应",
                )
            op.stage = "WAIT_TERM"
            return
        raise _rc_error(
            index,
            f"阶段不匹配：当前阶段 {op.stage} 不等待激活确认，却收到正确认",
        )

    # rc.cot == COT_ACTIVATION_TERM：激活终止只能由子站给出。
    if direction != SERVER:
        raise _rc_error(
            index,
            "遥控激活终止（传送原因 10）只能由子站给出，主站不得发送终止",
        )
    if op is None:
        raise _rc_error(
            index,
            f"公共地址 {rc.coa}、信息对象 {rc.ioa} 的激活终止没有对应的遥控操作",
        )
    if op.stage != "WAIT_TERM":
        raise _rc_error(
            index,
            f"阶段不匹配：当前阶段 {op.stage} 尚未取得执行正确认，不能接受激活终止",
        )
    if rc.scs != op.scs or rc.qoc != op.exec_qoc:
        raise _rc_error(
            index,
            "激活终止的命令状态(SCS)或限定词(QOC)与执行激活不对应",
        )
    del ops[key]
    counts["completed"] += 1


def audit_request(body: object) -> dict:
    """核验一次审计请求，成功返回结果字典，违规抛出 :class:`AuditError`。"""
    if not isinstance(body, dict):
        raise AuditError(ErrorCode.INVALID_REQUEST, -1, "请求体必须为 JSON 对象")

    max_window = body.get("maxWindow", body.get("maxUnconfirmedWindow"))
    if isinstance(max_window, bool) or not isinstance(max_window, int):
        raise AuditError(
            ErrorCode.INVALID_REQUEST, -1, "maxWindow 必须为整数"
        )
    if not (MIN_WINDOW <= max_window <= MAX_WINDOW):
        raise AuditError(
            ErrorCode.INVALID_REQUEST,
            -1,
            f"maxWindow 必须在 {MIN_WINDOW}..{MAX_WINDOW} 之间",
        )

    # 可选遥控裁决：省略 remoteControl.maxSelectDelayUs 时原契约不变。
    max_select_delay_us: Optional[int] = None
    remote_control = body.get("remoteControl")
    if remote_control is not None:
        if not isinstance(remote_control, dict):
            raise AuditError(
                ErrorCode.INVALID_REQUEST,
                -1,
                "remoteControl 必须为 JSON 对象",
            )
        if "maxSelectDelayUs" in remote_control:
            delay = remote_control["maxSelectDelayUs"]
            if isinstance(delay, bool) or not isinstance(delay, int):
                raise AuditError(
                    ErrorCode.INVALID_REQUEST,
                    -1,
                    "remoteControl.maxSelectDelayUs 必须为整数",
                )
            if not (MIN_SELECT_DELAY_US <= delay <= MAX_SELECT_DELAY_US):
                raise AuditError(
                    ErrorCode.INVALID_REQUEST,
                    -1,
                    f"remoteControl.maxSelectDelayUs 必须在 "
                    f"{MIN_SELECT_DELAY_US}..{MAX_SELECT_DELAY_US} 之间",
                )
            max_select_delay_us = delay

    raw_frames = body.get("frames")
    if not isinstance(raw_frames, list) or not raw_frames:
        raise AuditError(
            ErrorCode.INVALID_REQUEST, -1, "frames 必须为包含 1 个以上帧的数组"
        )
    if len(raw_frames) > MAX_FRAMES:
        raise AuditError(
            ErrorCode.INVALID_REQUEST,
            -1,
            f"frames 数量超过上限 {MAX_FRAMES}",
        )

    frames: list[tuple[str, Optional[int], ParsedFrame]] = []
    previous_ts: Optional[int] = None
    for index, item in enumerate(raw_frames):
        if not isinstance(item, dict):
            raise AuditError(
                ErrorCode.INVALID_REQUEST, index, "每一帧必须为 JSON 对象"
            )
        direction = normalize_direction(item.get("direction"))
        if direction is None:
            raise AuditError(
                ErrorCode.INVALID_REQUEST,
                index,
                "direction 必须为 client 或 server（也接受 master/slave 等别名）",
            )
        captured_at = item.get("capturedAtUs")
        if captured_at is not None:
            if isinstance(captured_at, bool) or not isinstance(captured_at, int):
                raise AuditError(
                    ErrorCode.INVALID_REQUEST,
                    index,
                    "capturedAtUs 必须为整数微秒时间戳",
                )
            if captured_at < 0:
                raise AuditError(
                    ErrorCode.INVALID_REQUEST,
                    index,
                    "capturedAtUs 不能为负数",
                )
            if previous_ts is not None and captured_at < previous_ts:
                raise AuditError(
                    ErrorCode.FRAMES_NOT_ORDERED,
                    index,
                    "capturedAtUs 早于之前的帧，帧未按非递减顺序排列",
                )
            previous_ts = captured_at
        try:
            parsed = parse_apdu(item.get("apdu"))
        except AuditError as exc:
            # 解析期错误没有帧下标，在此绑定到当前帧。
            raise AuditError(exc.code, index, exc.message) from None
        frames.append((direction, captured_at, parsed))

    return _audit(frames, max_window, max_select_delay_us)


def _audit(
    frames: list[tuple[str, Optional[int], ParsedFrame]],
    max_window: int,
    max_select_delay_us: Optional[int] = None,
) -> dict:
    rc_enabled = max_select_delay_us is not None
    states = {CLIENT: _PeerState(), SERVER: _PeerState()}
    # 每类 U 服务至多一个待配对 act：(发起方向, 帧下标)。
    pending: dict[str, Optional[tuple[str, int]]] = {
        "STARTDT": None,
        "STOPDT": None,
        "TESTFR": None,
    }
    counts = {
        "i": {CLIENT: 0, SERVER: 0},
        "u_act": {"STARTDT": 0, "STOPDT": 0, "TESTFR": 0},
        "u_con": {"STARTDT": 0, "STOPDT": 0, "TESTFR": 0},
        "u_paired": {"STARTDT": 0, "STOPDT": 0, "TESTFR": 0},
    }
    # 遥控裁决状态：键为 (公共地址, 信息对象地址)，不同对象允许交错。
    rc_ops: dict[tuple[int, int], _RemoteControlOp] = {}
    rc_counts = {"completed": 0, "rejected": 0}
    started = False

    for index, (direction, captured_at, frame) in enumerate(frames):
        peer = states[direction]
        remote = states[_opposite(direction)]

        # 时间证据是全局的：任何一帧的时间戳一旦证明某个已正确认的选择
        # 超过执行时限仍无执行激活，即判超时，定位到该操作最早的选择激活帧。
        if rc_enabled and captured_at is not None:
            _sweep_rc_timeouts(rc_ops, captured_at, max_select_delay_us)

        if frame.kind == "U":
            assert frame.u_type is not None
            started = _apply_u(
                frame.u_type, bool(frame.u_act), direction, index,
                pending, counts, started,
            )
            continue

        # I 帧只能出现在 STARTDT 已确认、STOPDT 未确认的数据传送阶段；
        # 阶段判定先于序号/确认号核验，以便最早定位该帧。
        if frame.kind == "I" and not started:
            raise AuditError(
                ErrorCode.I_FRAME_OUTSIDE_PHASE,
                index,
                "I 帧出现在 STARTDT 确认之前或 STOPDT 确认之后的数据传送阶段之外",
            )

        # I/S 帧均携带 N(R)，先核验确认号。
        assert frame.recv_seq is not None
        ack = frame.recv_seq
        if ack < peer.last_ack:
            raise AuditError(
                ErrorCode.ACK_BACKWARDS,
                index,
                f"确认号倒退：本端此前已确认到 {peer.last_ack}，本帧 N(R)={ack}",
            )
        if ack > remote.next_send:
            raise AuditError(
                ErrorCode.ACK_AHEAD,
                index,
                f"确认号越过对端已发送数据：对端已发送 {remote.next_send} 个 I 帧，"
                f"本帧 N(R)={ack}",
            )
        peer.last_ack = ack

        if frame.kind == "S":
            continue

        assert frame.send_seq is not None
        if frame.send_seq != peer.next_send:
            raise AuditError(
                ErrorCode.SEND_SEQUENCE_INVALID,
                index,
                f"发送序号失序：期望 N(S)={peer.next_send}，本帧 N(S)={frame.send_seq}",
            )
        peer.next_send += 1
        counts["i"][direction] += 1

        outstanding = peer.next_send - remote.last_ack
        if outstanding > max_window:
            raise AuditError(
                ErrorCode.WINDOW_EXCEEDED,
                index,
                f"本端未确认 I 帧数达到 {outstanding}，"
                f"超过最大未确认窗口 {max_window}",
            )

        # 传输层（控制域/序号/窗口）合法不代表遥控操作可采信：
        # 启用遥控裁决后，再对 Type 45 单对象 ASDU 重建选择/执行/终止证据链。
        if rc_enabled and frame.asdu_raw and frame.asdu_raw[0] == RC_TYPE_ID:
            try:
                rc = parse_remote_control(frame.asdu_raw)
            except AuditError as exc:
                raise AuditError(exc.code, index, exc.message) from None
            _apply_remote_control(
                rc,
                direction,
                index,
                captured_at,
                rc_ops,
                rc_counts,
            )

    # 会话结束时仍有 act 未与相反方向 con 配对：定位最早的未配对 act。
    earliest: Optional[tuple[int, str]] = None
    for u_type, mark in pending.items():
        if mark is not None:
            act_index = mark[1]
            if earliest is None or act_index < earliest[0]:
                earliest = (
                    act_index,
                    f"会话结束时 {u_type} act 仍未收到相反方向的 con 配对",
                )
    if earliest is not None:
        raise AuditError(
            ErrorCode.HANDSHAKE_UNMATCHED, earliest[0], earliest[1]
        )

    # 会话结束仍悬挂的遥控操作：若选择正确认后超过执行时限判超时，
    # 否则判未终结；定位到最早悬挂操作的选择激活帧。
    if rc_enabled:
        last_ts = frames[-1][1] if frames else None
        rc_earliest: Optional[tuple[int, str, ErrorCode]] = None
        for op in rc_ops.values():
            if (
                op.stage == "WAIT_EXECUTE"
                and op.select_con_ts is not None
                and last_ts is not None
                and last_ts - op.select_con_ts > max_select_delay_us
            ):
                message = (
                    f"选择正确认后 {last_ts - op.select_con_ts} 微秒内未见执行激活，"
                    f"超过时限 {max_select_delay_us} 微秒，会话结束仍未执行"
                )
                code = ErrorCode.REMOTE_CONTROL_TIMEOUT
            else:
                message = _rc_unterm_message(op)
                code = ErrorCode.REMOTE_CONTROL_UNTERMINATED
            candidate = (op.select_index, message, code)
            if rc_earliest is None or op.select_index < rc_earliest[0]:
                rc_earliest = candidate
        if rc_earliest is not None:
            raise AuditError(rc_earliest[2], rc_earliest[0], rc_earliest[1])

    result = {
        "iFrames": {
            CLIENT: counts["i"][CLIENT],
            SERVER: counts["i"][SERVER],
        },
        "outstanding": {
            # client 已发送但 server 尚未确认的 I 帧数，反之亦然。
            CLIENT: states[CLIENT].next_send - states[SERVER].last_ack,
            SERVER: states[SERVER].next_send - states[CLIENT].last_ack,
        },
        "handshakes": {
            name: {
                "act": counts["u_act"][name],
                "con": counts["u_con"][name],
                "paired": counts["u_paired"][name],
            }
            for name in ("STARTDT", "STOPDT", "TESTFR")
        },
    }
    if rc_enabled:
        # 启用遥控裁决后新增完成/拒绝计数；省略 remoteControl 时原契约不变。
        result["completed"] = rc_counts["completed"]
        result["rejected"] = rc_counts["rejected"]
    return {"ok": True, "result": result}


def _rc_unterm_message(op: _RemoteControlOp) -> str:
    stage_messages = {
        "SELECT_WAIT_CON": "选择激活尚未取得子站激活确认",
        "WAIT_EXECUTE": "选择正确认后未见时限内的执行激活及后续确认、终止",
        "EXEC_WAIT_CON": "执行激活尚未取得子站激活确认",
        "WAIT_TERM": "执行正确认后尚未取得激活终止",
    }
    return "会话结束时遥控操作仍悬挂：" + stage_messages[op.stage]


def _sweep_rc_timeouts(
    ops: dict[tuple[int, int], _RemoteControlOp],
    now_ts: int,
    max_select_delay_us: Optional[int],
) -> None:
    """按当前帧时间戳巡检所有等待执行激活的操作，超时即判 REMOTE_CONTROL_TIMEOUT。

    定位到该操作最早的选择激活帧（最早受影响证据）。
    """
    if max_select_delay_us is None:
        return
    earliest_index: Optional[int] = None
    earliest_message = ""
    for op in ops.values():
        if op.stage != "WAIT_EXECUTE" or op.select_con_ts is None:
            continue
        elapsed = now_ts - op.select_con_ts
        if elapsed > max_select_delay_us:
            if earliest_index is None or op.select_index < earliest_index:
                earliest_index = op.select_index
                earliest_message = (
                    f"选择正确认后 {elapsed} 微秒内未见执行激活，"
                    f"超过时限 {max_select_delay_us} 微秒"
                )
    if earliest_index is not None:
        raise AuditError(
            ErrorCode.REMOTE_CONTROL_TIMEOUT, earliest_index, earliest_message
        )


def _apply_u(
    u_type: str,
    is_act: bool,
    direction: str,
    index: int,
    pending: dict,
    counts: dict,
    started: bool,
) -> bool:
    """处理一帧 U 格式原语，返回更新后的 started（数据传送阶段）状态。"""
    counts["u_act" if is_act else "u_con"][u_type] += 1
    mark = pending[u_type]

    if is_act:
        # TESTFR 可在任意阶段出现；STARTDT/STOPDT 的阶段合法性仅约束 I 帧，
        # 这里只禁止同一服务存在尚未配对的 act 时再次发起。
        if mark is not None:
            raise AuditError(
                ErrorCode.HANDSHAKE_OVERLAP,
                index,
                f"上一个 {u_type} act 尚未收到相反方向的 con，又出现新的 act",
            )
        pending[u_type] = (direction, index)
        return started

    # con 必须与相反方向上待配对的 act 成对。
    if mark is None:
        raise AuditError(
            ErrorCode.HANDSHAKE_UNMATCHED,
            index,
            f"{u_type} con 没有来自相反方向的待配对 act",
        )
    act_direction, _ = mark
    if act_direction != _opposite(direction):
        raise AuditError(
            ErrorCode.HANDSHAKE_UNMATCHED,
            index,
            f"{u_type} con 与 act 来自同一方向，act/con 必须由相反方向配对",
        )

    pending[u_type] = None
    counts["u_paired"][u_type] += 1
    if u_type == "STARTDT":
        return True
    if u_type == "STOPDT":
        return False
    return started
