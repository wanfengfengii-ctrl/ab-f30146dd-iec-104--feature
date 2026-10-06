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

# 遥控选择/执行裁决参数（remoteControl.maxSelectDelayUs）
MIN_SELECT_DELAY_US = 1
MAX_SELECT_DELAY_US = 60_000_000
# C_SC_NA_1：单命令（Single command），Type 45，单对象 ASDU。
C_SC_NA_1 = 45
_RC_ASDU_LEN = 10  # 类型(1)+VSQ(1)+COT(1)+原发地址(1)+公共地址(2)+IOA(3)+QOS(1)
# 传输原因（COT）
COT_ACTIVATION = 6       # 激活（主站发起选择/执行）
COT_ACT_CONFIRM = 7      # 激活确认（子站，可带 P/N 负确认）
COT_ACT_TERMINATION = 10  # 激活终止（子站）

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
    REMOTE_CONTROL_REJECTED = "REMOTE_CONTROL_REJECTED"

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
    ErrorCode.REMOTE_CONTROL_REJECTED: 422,
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
    # I 帧携带的 ASDU（非 Type 45 时 rc 为 None）
    rc: Optional["RemoteControlASDU"] = None


@dataclass(frozen=True)
class RemoteControlASDU:
    """C_SC_NA_1（Type 45）单命令 ASDU 的取证要素。

    结构异常（长度/VSQ）也照常提取原始字段，由会话状态机在启用遥控裁决时
    按格式不匹配拒绝；未启用时这些帧与普通 I 帧无异。
    """

    cot: int
    cause_tx: int
    common_addr: int
    ioa: int
    qos: int
    negative: bool
    vsq: int
    asdu_len: int

    @property
    def structurally_single(self) -> bool:
        """是否为恰含一个信息对象、长度正确的单对象 ASDU。"""
        return self.asdu_len == _RC_ASDU_LEN and self.vsq == 0x01


_U_FUNCTIONS = {
    0x04: ("STARTDT", True),   # 0x07
    0x08: ("STARTDT", False),  # 0x0B
    0x10: ("STOPDT", True),    # 0x13
    0x20: ("STOPDT", False),   # 0x23
    0x40: ("TESTFR", True),    # 0x43
    0x80: ("TESTFR", False),   # 0x83
}


def _parse_remote_control(asdu: bytes) -> Optional[RemoteControlASDU]:
    """在 ASDU 类型标识为 C_SC_NA_1（Type 45）时提取遥控要素，否则返回 None。

    结构异常（长度/VSQ）也照常提取已有字段，由会话状态机在启用遥控裁决时
    按格式不匹配拒绝；未启用时这些帧与普通 I 帧无异。
    """
    if not asdu or asdu[0] != C_SC_NA_1:
        return None

    def byte_at(offset: int) -> int:
        return asdu[offset] if offset < len(asdu) else 0

    vsq = byte_at(1)
    cot = byte_at(2) & 0x3F
    negative = bool(byte_at(2) & 0x40)
    cause_tx = byte_at(3)
    common_addr = byte_at(4) | (byte_at(5) << 8)
    ioa = byte_at(6) | (byte_at(7) << 8) | (byte_at(8) << 16)
    qos = byte_at(9)
    return RemoteControlASDU(
        cot=cot,
        cause_tx=cause_tx,
        common_addr=common_addr,
        ioa=ioa,
        qos=qos,
        negative=negative,
        vsq=vsq,
        asdu_len=len(asdu),
    )


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
            rc=_parse_remote_control(data[6:]),
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


# 遥控操作的各阶段：等待选择确认 -> 等待执行 -> 等待执行确认 -> 等待终止。
_RC_AWAIT_SELECT_CON = "await_select_con"
_RC_AWAIT_EXEC = "await_exec"
_RC_AWAIT_EXEC_CON = "await_exec_con"
_RC_AWAIT_TERM = "await_term"


@dataclass
class _RemoteControlOp:
    """同一（公共地址, 信息对象地址）上一次选择-执行操作的证据链状态。"""

    stage: str
    select_index: int
    select_ts: int
    select_qos: int
    exec_index: int = -1
    exec_qos: int = 0


class _RemoteControlTracker:
    """裁决 Type 45 单命令的选择/执行/确认/终止证据链。

    不同信息对象的操作可交错；同一对象在证据链闭合（completed/rejected）前
    不得重入。子站负确认是合法证据：操作就此结束并计入 rejected，审计仍通过；
    格式、方向、命令状态、限定词、阶段不匹配、超时或会话结束仍悬挂则拒绝采信，
    抛出 :class:`AuditError`，下标尽量指向证据链中最早的相关帧。
    """

    def __init__(self, max_select_delay_us: int):
        self.max_select_delay_us = max_select_delay_us
        self.ops: dict[tuple[int, int], _RemoteControlOp] = {}
        self.completed = 0
        self.rejected = 0

    def _error(self, index: int, message: str) -> None:
        raise AuditError(ErrorCode.REMOTE_CONTROL_REJECTED, index, message)

    def feed(
        self,
        direction: str,
        ts: int,
        index: int,
        rc: RemoteControlASDU,
    ) -> None:
        if not rc.structurally_single:
            self._error(
                index,
                "遥控帧格式不匹配：C_SC_NA_1 必须为单信息对象"
                "（VSQ=0x01）且 ASDU 恰为 10 字节",
            )

        key = (rc.common_addr, rc.ioa)
        op = self.ops.get(key)
        if direction == CLIENT:
            self._feed_client(rc, key, op, ts, index)
        else:
            self._feed_server(rc, key, op, index)

    def _feed_client(
        self,
        rc: RemoteControlASDU,
        key: tuple[int, int],
        op: Optional[_RemoteControlOp],
        ts: int,
        index: int,
    ) -> None:
        # 方向/状态：主站只能出现 COT=6 激活（选择或执行），且不携带 P/N 位。
        if rc.negative:
            self._error(
                index,
                "方向与字段不匹配：P/N 负确认位只能出现在子站的激活确认中，"
                "主站遥控激活帧不得置位",
            )
        if rc.cot != COT_ACTIVATION:
            self._error(
                index,
                f"方向与阶段不匹配：主站遥控帧命令状态为 COT={rc.cot}，"
                "主站只能发送激活（COT=6）的选择或执行命令",
            )

        is_select = bool(rc.qos & 0x80)  # QOS 的 SE 位：1=选择，0=执行
        if is_select:
            if op is not None:
                self._error(
                    index,
                    "同一公共地址/信息对象的遥控操作尚未闭合（completed/rejected）"
                    "又发起选择激活，同一对象禁止重入",
                )
            self.ops[key] = _RemoteControlOp(
                stage=_RC_AWAIT_SELECT_CON,
                select_index=index,
                select_ts=ts,
                select_qos=rc.qos,
            )
            return

        # 执行激活：必须先取得匹配的选择正确认，且落在选择时限内。
        if op is None:
            self._error(
                index,
                "阶段不匹配：执行激活之前缺少同对象选择激活及其子站正确认"
                "（先选择、取得正确认后才允许执行）",
            )
        if op.stage != _RC_AWAIT_EXEC:
            self._error(
                index,
                "阶段不匹配：同一公共地址/信息对象的上一条遥控操作尚未闭合"
                "（completed/rejected）即出现执行激活，同对象不得重入",
            )
        delay_us = ts - op.select_ts
        if delay_us > self.max_select_delay_us:
            # 超时证据链最早的一帧是选择激活。
            self._error(
                op.select_index,
                f"执行激活距选择激活 {delay_us}μs，超过 maxSelectDelayUs="
                f"{self.max_select_delay_us}μs 的选择时限",
            )
        op.stage = _RC_AWAIT_EXEC_CON
        op.exec_index = index
        op.exec_qos = rc.qos

    def _feed_server(
        self,
        rc: RemoteControlASDU,
        key: tuple[int, int],
        op: Optional[_RemoteControlOp],
        index: int,
    ) -> None:
        if rc.cot == COT_ACT_CONFIRM:
            self._feed_confirm(rc, key, op, index)
            return
        if rc.cot == COT_ACT_TERMINATION:
            self._feed_termination(rc, op, index)
            return
        self._error(
            index,
            f"方向与阶段不匹配：子站遥控帧命令状态为 COT={rc.cot}，"
            "子站只能发送激活确认（COT=7）或激活终止（COT=10）",
        )

    def _feed_confirm(
        self,
        rc: RemoteControlASDU,
        key: tuple[int, int],
        op: Optional[_RemoteControlOp],
        index: int,
    ) -> None:
        # 必须存在来自相反方向、同公共地址/IOA 且正等待确认的选择或执行激活。
        if op is None or op.stage not in (
            _RC_AWAIT_SELECT_CON,
            _RC_AWAIT_EXEC_CON,
        ):
            self._error(
                index,
                "阶段不匹配：子站激活确认没有对应的待确认选择/执行激活"
                "（激活确认必须由相反方向的同对象激活触发）",
            )
        assert op is not None
        awaiting_select = op.stage == _RC_AWAIT_SELECT_CON
        wanted_qos = op.select_qos if awaiting_select else op.exec_qos
        if rc.qos != wanted_qos:
            self._error(
                index,
                f"字段不匹配：激活确认的限定词 QOS=0x{rc.qos:02x} 与对应激活的 "
                f"QOS=0x{wanted_qos:02x} 不一致",
            )

        if rc.negative:
            # 负确认是合法的取证结果：操作结束、计为 rejected，审计继续。
            self.ops.pop(key, None)
            self.rejected += 1
            return

        if awaiting_select:
            op.stage = _RC_AWAIT_EXEC
        else:
            op.stage = _RC_AWAIT_TERM

    def _feed_termination(
        self,
        rc: RemoteControlASDU,
        op: Optional[_RemoteControlOp],
        index: int,
    ) -> None:
        if op is None or op.stage != _RC_AWAIT_TERM:
            self._error(
                index,
                "阶段不匹配：激活终止之前缺少同对象的执行激活及其正确认，"
                "终止证据必须闭合完整的选择-执行证据链",
            )
        assert op is not None
        if rc.negative:
            self._error(
                index,
                "字段不匹配：激活终止（COT=10）帧不得携带 P/N=1 负确认位",
            )
        if rc.qos != op.exec_qos:
            self._error(
                index,
                f"字段不匹配：激活终止的限定词 QOS=0x{rc.qos:02x} 与执行激活的 "
                f"QOS=0x{op.exec_qos:02x} 不一致",
            )
        self.ops.pop((rc.common_addr, rc.ioa), None)
        self.completed += 1

    def finish(self, last_ts: int) -> Optional[tuple[int, str]]:
        """会话结束时核对仍悬挂的操作，返回最早未闭合帧的下标与说明。"""
        earliest: Optional[tuple[int, str]] = None
        for op in self.ops.values():
            if op.stage == _RC_AWAIT_SELECT_CON:
                mark = (
                    op.select_index,
                    "会话结束时选择激活仍未取得子站匹配的激活确认",
                )
            elif op.stage == _RC_AWAIT_EXEC:
                if last_ts - op.select_ts > self.max_select_delay_us:
                    mark = (
                        op.select_index,
                        "选择正确认后超过 maxSelectDelayUs 选择时限"
                        "仍未收到执行激活",
                    )
                else:
                    mark = (
                        op.select_index,
                        "会话结束时选择激活虽已确认，但缺少时限内的执行激活、"
                        "执行确认与激活终止证据",
                    )
            elif op.stage == _RC_AWAIT_EXEC_CON:
                mark = (
                    op.select_index,
                    "会话结束时执行激活仍未取得子站匹配的激活确认",
                )
            else:  # _RC_AWAIT_TERM
                mark = (
                    op.select_index,
                    "会话结束时执行激活已确认但仍缺少匹配的激活终止证据",
                )
            if earliest is None or mark[0] < earliest[0]:
                earliest = mark
        return earliest



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

    select_delay = None
    remote_control = body.get("remoteControl")
    if remote_control is not None:
        if not isinstance(remote_control, dict):
            raise AuditError(
                ErrorCode.INVALID_REQUEST,
                -1,
                "remoteControl 必须为 JSON 对象",
            )
        if "maxSelectDelayUs" in remote_control:
            select_delay = remote_control["maxSelectDelayUs"]
            if isinstance(select_delay, bool) or not isinstance(select_delay, int):
                raise AuditError(
                    ErrorCode.INVALID_REQUEST,
                    -1,
                    "remoteControl.maxSelectDelayUs 必须为整数",
                )
            if not (MIN_SELECT_DELAY_US <= select_delay <= MAX_SELECT_DELAY_US):
                raise AuditError(
                    ErrorCode.INVALID_REQUEST,
                    -1,
                    f"remoteControl.maxSelectDelayUs 必须在 "
                    f"{MIN_SELECT_DELAY_US}..{MAX_SELECT_DELAY_US} 之间",
                )

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
        if select_delay is not None and captured_at is None:
            raise AuditError(
                ErrorCode.INVALID_REQUEST,
                index,
                "启用 remoteControl 裁决时每一帧都必须提供 capturedAtUs",
            )
        frames.append((direction, captured_at, parsed))

    return _audit(frames, max_window, select_delay)


def _audit(
    frames: list[tuple[str, Optional[int], ParsedFrame]],
    max_window: int,
    select_delay: Optional[int] = None,
) -> dict:
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
    started = False
    tracker: Optional[_RemoteControlTracker] = (
        _RemoteControlTracker(select_delay) if select_delay is not None else None
    )
    last_ts: Optional[int] = None

    for index, (direction, captured_at, frame) in enumerate(frames):
        if captured_at is not None:
            last_ts = captured_at
        peer = states[direction]
        remote = states[_opposite(direction)]

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

        # 传输层（控制域/序号/窗口/阶段）全部合法后，再裁决遥控命令证据链；
        # 传输序号合法不代表遥控操作本身可采信。
        if tracker is not None and frame.rc is not None:
            assert captured_at is not None
            tracker.feed(direction, captured_at, index, frame.rc)

    # 会话结束时仍有 act 未与相反方向 con 配对：定位最早的未配对 act。
    handshake_mark: Optional[tuple[int, str]] = None
    for u_type, mark in pending.items():
        if mark is not None:
            act_index = mark[1]
            if handshake_mark is None or act_index < handshake_mark[0]:
                handshake_mark = (
                    act_index,
                    f"会话结束时 {u_type} act 仍未收到相反方向的 con 配对",
                )

    # 遥控操作同样可能在会话结束时仍悬挂；与 U 帧悬挂一起取最早的一帧。
    rc_mark: Optional[tuple[int, str]] = None
    if tracker is not None:
        assert last_ts is not None
        rc_mark = tracker.finish(last_ts)

    if rc_mark is not None and (
        handshake_mark is None or rc_mark[0] < handshake_mark[0]
    ):
        raise AuditError(
            ErrorCode.REMOTE_CONTROL_REJECTED, rc_mark[0], rc_mark[1]
        )
    if handshake_mark is not None:
        raise AuditError(
            ErrorCode.HANDSHAKE_UNMATCHED,
            handshake_mark[0],
            handshake_mark[1],
        )

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
    if tracker is not None:
        # 省略 remoteControl 时不出现该字段，原契约保持不变。
        result["remoteControl"] = {
            "completed": tracker.completed,
            "rejected": tracker.rejected,
        }
    return {"ok": True, "result": result}


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
