"""Type 45 C_SC_NA_1 单对象遥控选择/执行/终止证据链核验测试。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

from protocol import AuditError, ErrorCode, audit_request  # noqa: E402


def rc_frame(send, recv, cot, *, direction="client", ts=0, coa=1, ioa=10,
             scs=1, qoc=0x80, pn=False):
    """构造携带 Type 45 单对象遥控 ASDU 的 I 帧。

    select: qoc=0x80（S/E=1）；execute: qoc=0x00（S/E=0）。
    cot: 6=激活 7=激活确认 10=激活终止；pn=True 置 P/N 位。
    """
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
    apdu = (bytes([0x68, len(body)]) + body).hex()
    frame = {"direction": direction, "apdu": apdu}
    if ts is not None:
        frame["capturedAtUs"] = ts
    return frame


START = [
    {"direction": "client", "apdu": "680407000000", "capturedAtUs": 0},
    {"direction": "server", "apdu": "68040b000000", "capturedAtUs": 0},
]


def full_chain(ioa=10, start=100, delta=10, *, qoc_select=0x80,
               qoc_execute=0x00, scs=1, coa=1, cs0=0, ss0=0):
    """一条完整的 选择→选择确认→执行→执行确认→终止 证据链（5 帧）。

    cs0/ss0 为主站/子站进入该链时各自已发送的 I 帧数（序号从其接续）。
    """
    return [
        rc_frame(cs0, ss0, 6, ioa=ioa, qoc=qoc_select, scs=scs, coa=coa,
                 ts=start, direction="client"),
        rc_frame(ss0, cs0 + 1, 7, ioa=ioa, qoc=qoc_select, scs=scs, coa=coa,
                 ts=start + delta, direction="server"),
        rc_frame(cs0 + 1, ss0 + 1, 6, ioa=ioa, qoc=qoc_execute, scs=scs,
                 coa=coa, ts=start + 2 * delta, direction="client"),
        rc_frame(ss0 + 1, cs0 + 2, 7, ioa=ioa, qoc=qoc_execute, scs=scs,
                 coa=coa, ts=start + 3 * delta, direction="server"),
        rc_frame(ss0 + 2, cs0 + 2, 10, ioa=ioa, qoc=qoc_execute, scs=scs,
                 coa=coa, ts=start + 4 * delta, direction="server"),
    ]


def audit(frames, delay=1000, window=16, with_rc=True):
    body = {"frames": START + frames, "maxWindow": window}
    if with_rc:
        body["remoteControl"] = {"maxSelectDelayUs": delay}
    return audit_request(body)


def expect_error(frames, code, index, delay=1000, window=16):
    try:
        audit(frames, delay=delay, window=window)
    except AuditError as exc:
        assert exc.code is code, f"期望 {code}，实际 {exc.code}（{exc.message}）"
        assert exc.frame_index == index, (
            f"期望下标 {index}，实际 {exc.frame_index}（{exc.message}）"
        )
        return exc
    raise AssertionError(f"应当抛出 {code}，但核验通过了")


class RemoteControlContractTests(unittest.TestCase):
    def test_omitted_remote_control_keeps_contract(self):
        result = audit([rc_frame(0, 0, 6, qoc=0x00)], with_rc=False)["result"]
        self.assertNotIn("completed", result)
        self.assertNotIn("rejected", result)
        self.assertEqual(set(result), {"iFrames", "outstanding", "handshakes"})

    def test_empty_remote_control_object_enables_audit(self):
        # 空对象（未提供 maxSelectDelayUs）视为不启用，原契约不变。
        body = {"frames": START, "maxWindow": 16, "remoteControl": {}}
        result = audit_request(body)["result"]
        self.assertNotIn("completed", result)

    def test_delay_boundaries(self):
        for good in (1, 60_000_000):
            audit_request({
                "frames": START, "maxWindow": 16,
                "remoteControl": {"maxSelectDelayUs": good},
            })
        for bad in (0, -1, 60_000_001):
            with self.assertRaises(AuditError) as cm:
                audit_request({
                    "frames": START, "maxWindow": 16,
                    "remoteControl": {"maxSelectDelayUs": bad},
                })
            self.assertEqual(cm.exception.code, ErrorCode.INVALID_REQUEST)

    def test_delay_wrong_type(self):
        for bad in ("1000", 1.5, True, None):
            with self.assertRaises(AuditError) as cm:
                audit_request({
                    "frames": START, "maxWindow": 16,
                    "remoteControl": {"maxSelectDelayUs": bad},
                })
            self.assertEqual(cm.exception.code, ErrorCode.INVALID_REQUEST)

    def test_remote_control_not_object(self):
        with self.assertRaises(AuditError) as cm:
            audit_request({
                "frames": START, "maxWindow": 16, "remoteControl": [],
            })
        self.assertEqual(cm.exception.code, ErrorCode.INVALID_REQUEST)


class RemoteControlHappyPathTests(unittest.TestCase):
    def test_full_chain_completed(self):
        result = audit(full_chain())["result"]
        self.assertEqual(result["completed"], 1)
        self.assertEqual(result["rejected"], 0)

    def test_delay_boundary_equal_allowed(self):
        # 选择确认 t=110，执行 t=1110，间隔恰好 1000，等于上限允许。
        frames = [
            rc_frame(0, 0, 6, ts=100, qoc=0x80),
            rc_frame(0, 1, 7, ts=110, qoc=0x80, direction="server"),
            rc_frame(1, 1, 6, ts=1110, qoc=0x00),
            rc_frame(1, 2, 7, ts=1120, qoc=0x00, direction="server"),
            rc_frame(2, 2, 10, ts=1130, qoc=0x00, direction="server"),
        ]
        result = audit(frames, delay=1000)["result"]
        self.assertEqual(result["completed"], 1)

    def test_interleaved_different_objects_both_completed(self):
        # 交错：A 选择/确认，B 选择/确认，A 执行/确认/终止，B 执行/确认/终止。
        frames = [
            rc_frame(0, 0, 6, ioa=10, qoc=0x80, ts=100),
            rc_frame(1, 0, 6, ioa=20, qoc=0x80, ts=101),
            rc_frame(0, 2, 7, ioa=10, qoc=0x80, ts=102, direction="server"),
            rc_frame(1, 2, 7, ioa=20, qoc=0x80, ts=103, direction="server"),
            rc_frame(2, 1, 6, ioa=10, qoc=0x00, ts=104),
            rc_frame(3, 1, 6, ioa=20, qoc=0x00, ts=105),
            rc_frame(2, 4, 7, ioa=10, qoc=0x00, ts=106, direction="server"),
            rc_frame(3, 4, 7, ioa=20, qoc=0x00, ts=107, direction="server"),
            rc_frame(4, 4, 10, ioa=10, qoc=0x00, ts=108, direction="server"),
            rc_frame(5, 4, 10, ioa=20, qoc=0x00, ts=109, direction="server"),
        ]
        result = audit(frames)["result"]
        self.assertEqual(result["completed"], 2)
        self.assertEqual(result["rejected"], 0)

    def test_different_coa_same_ioa_are_distinct(self):
        frames = [
            rc_frame(0, 0, 6, coa=1, ioa=10, qoc=0x80, ts=100),
            rc_frame(1, 0, 6, coa=2, ioa=10, qoc=0x80, ts=101),
            rc_frame(0, 2, 7, coa=1, ioa=10, qoc=0x80, ts=102,
                     direction="server"),
            rc_frame(1, 2, 7, coa=2, ioa=10, qoc=0x80, ts=103,
                     direction="server"),
        ]
        # 两对象都停在 WAIT_EXECUTE，会话结束判未终结，但证明它们彼此独立。
        exc = expect_error(frames, ErrorCode.REMOTE_CONTROL_UNTERMINATED, 2)
        self.assertIn("悬挂", exc.message)

    def test_second_operation_after_completion_allowed(self):
        frames = full_chain(ioa=10, start=100, cs0=0, ss0=0)
        frames += full_chain(ioa=10, start=200, cs0=2, ss0=3)
        result = audit(frames)["result"]
        self.assertEqual(result["completed"], 2)

    def test_non_type45_asdu_not_judged(self):
        # Type 1 M_SP_NA_1 等非遥控 ASDU 不纳入遥控裁决。
        def other_i(send, recv, ts):
            asdu = bytes([1, 1, 3, 0, 1, 0, 0, 0, 0, 0x01])
            body = bytes([(send << 1) & 0xFF, (send << 1) >> 8,
                          (recv << 1) & 0xFF, (recv << 1) >> 8]) + asdu
            return {"direction": "client",
                    "apdu": (bytes([0x68, len(body)]) + body).hex(),
                    "capturedAtUs": ts}
        result = audit([other_i(0, 0, 100)])["result"]
        self.assertEqual(result["completed"], 0)


class RemoteControlNegativeAckTests(unittest.TestCase):
    def test_select_negative_ack_is_rejected(self):
        frames = [
            rc_frame(0, 0, 6, qoc=0x80, ts=100),
            rc_frame(0, 1, 7, qoc=0x80, pn=True, ts=110, direction="server"),
        ]
        result = audit(frames)["result"]
        self.assertEqual(result["rejected"], 1)
        self.assertEqual(result["completed"], 0)

    def test_execute_negative_ack_is_rejected(self):
        frames = [
            rc_frame(0, 0, 6, qoc=0x80, ts=100),
            rc_frame(0, 1, 7, qoc=0x80, ts=110, direction="server"),
            rc_frame(1, 1, 6, qoc=0x00, ts=120),
            rc_frame(1, 2, 7, qoc=0x00, pn=True, ts=130, direction="server"),
        ]
        result = audit(frames)["result"]
        self.assertEqual(result["rejected"], 1)

    def test_negative_ack_ends_operation_allowing_restart(self):
        frames = [
            rc_frame(0, 0, 6, qoc=0x80, ts=100),
            rc_frame(0, 1, 7, qoc=0x80, pn=True, ts=110, direction="server"),
        ]
        frames += full_chain(ioa=10, start=200, cs0=1, ss0=1)
        result = audit(frames)["result"]
        self.assertEqual(result["rejected"], 1)
        self.assertEqual(result["completed"], 1)

    def test_negative_ack_with_mismatched_qoc_rejected(self):
        frames = [
            rc_frame(0, 0, 6, qoc=0x80, ts=100),
            rc_frame(0, 1, 7, qoc=0x84, pn=True, ts=110, direction="server"),
        ]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_MISMATCH, 3)


class RemoteControlViolationTests(unittest.TestCase):
    def test_execute_without_select(self):
        expect_error(
            [rc_frame(0, 0, 6, qoc=0x00, ts=100)],
            ErrorCode.REMOTE_CONTROL_MISMATCH, 2,
        )

    def test_select_con_without_select(self):
        expect_error(
            [rc_frame(0, 0, 7, qoc=0x80, ts=100, direction="server")],
            ErrorCode.REMOTE_CONTROL_MISMATCH, 2,
        )

    def test_termination_without_chain(self):
        expect_error(
            [rc_frame(0, 0, 10, qoc=0x00, ts=100, direction="server")],
            ErrorCode.REMOTE_CONTROL_MISMATCH, 2,
        )

    def test_execute_before_select_confirmed(self):
        frames = [
            rc_frame(0, 0, 6, qoc=0x80, ts=100),
            rc_frame(1, 0, 6, qoc=0x00, ts=101),  # 未见选择确认即执行
        ]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_REENTRY, 3)

    def test_duplicate_select_is_reentry(self):
        frames = [
            rc_frame(0, 0, 6, qoc=0x80, ts=100),
            rc_frame(1, 0, 6, qoc=0x80, ts=101),
        ]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_REENTRY, 3)

    def test_select_while_waiting_execute_is_reentry(self):
        frames = [
            rc_frame(0, 0, 6, qoc=0x80, ts=100),
            rc_frame(0, 1, 7, qoc=0x80, ts=110, direction="server"),
            rc_frame(1, 1, 6, qoc=0x80, ts=120),  # 又发选择而非执行
        ]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_REENTRY, 4)

    def test_mismatched_ioa_on_select_con(self):
        frames = [
            rc_frame(0, 0, 6, ioa=10, qoc=0x80, ts=100),
            rc_frame(0, 1, 7, ioa=11, qoc=0x80, ts=110, direction="server"),
        ]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_MISMATCH, 3)

    def test_mismatched_coa_on_execute_con(self):
        frames = [
            rc_frame(0, 0, 6, coa=1, ioa=10, qoc=0x80, ts=100),
            rc_frame(0, 1, 7, coa=1, ioa=10, qoc=0x80, ts=110,
                     direction="server"),
            rc_frame(1, 1, 6, coa=1, ioa=10, qoc=0x00, ts=120),
            rc_frame(1, 2, 7, coa=2, ioa=10, qoc=0x00, ts=130,
                     direction="server"),
        ]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_MISMATCH, 5)

    def test_mismatched_scs_on_execute(self):
        frames = [
            rc_frame(0, 0, 6, scs=1, qoc=0x80, ts=100),
            rc_frame(0, 1, 7, scs=1, qoc=0x80, ts=110, direction="server"),
            rc_frame(1, 1, 6, scs=0, qoc=0x00, ts=120),
        ]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_MISMATCH, 4)

    def test_mismatched_qu_on_execute(self):
        frames = [
            rc_frame(0, 0, 6, qoc=0x84, ts=100),  # QU=1
            rc_frame(0, 1, 7, qoc=0x84, ts=110, direction="server"),
            rc_frame(1, 1, 6, qoc=0x08, ts=120),  # QU=2
        ]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_MISMATCH, 4)

    def test_se_bit_mismatch_between_select_and_execute(self):
        # 选择用 S/E=1，执行确认阶段却回 S/E=1 限定词，属于字段不对应。
        frames = [
            rc_frame(0, 0, 6, qoc=0x80, ts=100),
            rc_frame(0, 1, 7, qoc=0x80, ts=110, direction="server"),
            rc_frame(1, 1, 6, qoc=0x00, ts=120),
            rc_frame(1, 2, 7, qoc=0x80, ts=130, direction="server"),
        ]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_MISMATCH, 5)

    def test_activation_from_server_is_direction_error(self):
        expect_error(
            [rc_frame(0, 0, 6, qoc=0x80, ts=100, direction="server")],
            ErrorCode.REMOTE_CONTROL_MISMATCH, 2,
        )

    def test_confirmation_from_client_is_direction_error(self):
        frames = [
            rc_frame(0, 0, 6, qoc=0x80, ts=100),
            rc_frame(1, 0, 7, qoc=0x80, ts=110, direction="client"),
        ]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_MISMATCH, 3)

    def test_termination_from_client_is_direction_error(self):
        frames = full_chain()[:4]
        frames.append(rc_frame(2, 2, 10, qoc=0x00, ts=200,
                               direction="client"))
        expect_error(frames, ErrorCode.REMOTE_CONTROL_MISMATCH, 6)

    def test_termination_before_execution_confirmed(self):
        frames = [
            rc_frame(0, 0, 6, qoc=0x80, ts=100),
            rc_frame(0, 1, 7, qoc=0x80, ts=110, direction="server"),
            rc_frame(1, 1, 6, qoc=0x00, ts=120),
            rc_frame(1, 2, 10, qoc=0x00, ts=130, direction="server"),
        ]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_MISMATCH, 5)

    def test_select_delay_exceeded(self):
        frames = [
            rc_frame(0, 0, 6, qoc=0x80, ts=100),
            rc_frame(0, 1, 7, qoc=0x80, ts=110, direction="server"),
            rc_frame(1, 1, 6, qoc=0x00, ts=1112),  # 间隔 1002 > 1000
        ]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_TIMEOUT, 2, delay=1000)

    def test_select_delay_exceeded_observed_by_later_unrelated_frame(self):
        # 超时由后续 U 帧的时间戳暴露，仍定位到最早的选择激活帧。
        frames = [
            rc_frame(0, 0, 6, ioa=10, qoc=0x80, ts=100),
            rc_frame(0, 1, 7, ioa=10, qoc=0x80, ts=110, direction="server"),
            {"direction": "client", "apdu": "680443000000",
             "capturedAtUs": 2000},  # TESTFR act
        ]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_TIMEOUT, 2, delay=1000)

    def test_session_end_select_unconfirmed(self):
        frames = [rc_frame(0, 0, 6, qoc=0x80, ts=100)]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_UNTERMINATED, 2)

    def test_session_end_no_execution(self):
        frames = [
            rc_frame(0, 0, 6, qoc=0x80, ts=100),
            rc_frame(0, 1, 7, qoc=0x80, ts=110, direction="server"),
        ]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_UNTERMINATED, 2)

    def test_session_end_no_termination(self):
        frames = [
            rc_frame(0, 0, 6, qoc=0x80, ts=100),
            rc_frame(0, 1, 7, qoc=0x80, ts=110, direction="server"),
            rc_frame(1, 1, 6, qoc=0x00, ts=120),
            rc_frame(1, 2, 7, qoc=0x00, ts=130, direction="server"),
        ]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_UNTERMINATED, 2)

    def test_session_end_timeout_uses_timeout_code(self):
        # 会话内已出现超出时限的时间证据：超时优先于未终结。
        frames = [
            rc_frame(0, 0, 6, qoc=0x80, ts=100),
            rc_frame(0, 1, 7, qoc=0x80, ts=110, direction="server"),
            {"direction": "client", "apdu": "680443000000",
             "capturedAtUs": 2000},  # TESTFR act 证明已过 1000us 时限
        ]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_TIMEOUT, 2, delay=1000)

    def test_timeout_without_timestamps_is_unterminated(self):
        # 全程无时间戳，无法证明超时；会话结束悬挂判未终结。
        frames = [
            rc_frame(0, 0, 6, qoc=0x80, ts=None),
            rc_frame(0, 1, 7, qoc=0x80, ts=None, direction="server"),
        ]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_UNTERMINATED, 2,
                     delay=1000)

    def test_earliest_pending_select_index_reported(self):
        frames = [
            rc_frame(0, 0, 6, ioa=10, qoc=0x80, ts=100),
            rc_frame(1, 0, 6, ioa=20, qoc=0x80, ts=101),
        ]
        expect_error(frames, ErrorCode.REMOTE_CONTROL_UNTERMINATED, 2)


class RemoteControlFormatTests(unittest.TestCase):
    def _raw_rc_frame(self, asdu: bytes, send=0, recv=0):
        body = bytes([(send << 1) & 0xFF, (send << 1) >> 8,
                      (recv << 1) & 0xFF, (recv << 1) >> 8]) + asdu
        return {"direction": "client",
                "apdu": (bytes([0x68, len(body)]) + body).hex(),
                "capturedAtUs": 100}

    def test_wrong_length(self):
        asdu = bytes([45, 1, 6, 0, 1, 0, 10, 0, 0, 1])  # 10 字节，缺 QOC
        expect_error([self._raw_rc_frame(asdu)],
                     ErrorCode.REMOTE_CONTROL_INVALID, 2)

    def test_vsq_not_single(self):
        asdu = bytes([45, 2, 6, 0, 1, 0, 10, 0, 0, 1, 0x80])
        expect_error([self._raw_rc_frame(asdu)],
                     ErrorCode.REMOTE_CONTROL_INVALID, 2)

    def test_unsupported_cot(self):
        asdu = bytes([45, 1, 9, 0, 1, 0, 10, 0, 0, 1, 0x80])  # COT=9 停用确认
        expect_error([self._raw_rc_frame(asdu)],
                     ErrorCode.REMOTE_CONTROL_INVALID, 2)

    def test_activation_with_pn_bit(self):
        asdu = bytes([45, 1, 6 | 0x40, 0, 1, 0, 10, 0, 0, 1, 0x80])
        expect_error([self._raw_rc_frame(asdu)],
                     ErrorCode.REMOTE_CONTROL_INVALID, 2)

    def test_termination_with_pn_bit(self):
        asdu = bytes([45, 1, 10 | 0x40, 0, 1, 0, 10, 0, 0, 1, 0x00])
        expect_error([self._raw_rc_frame(asdu)],
                     ErrorCode.REMOTE_CONTROL_INVALID, 2)

    def test_scs_reserved_bits(self):
        asdu = bytes([45, 1, 6, 0, 1, 0, 10, 0, 0, 2, 0x80])
        expect_error([self._raw_rc_frame(asdu)],
                     ErrorCode.REMOTE_CONTROL_INVALID, 2)

    def test_qoc_reserved_bits(self):
        asdu = bytes([45, 1, 6, 0, 1, 0, 10, 0, 0, 1, 0x81])
        expect_error([self._raw_rc_frame(asdu)],
                     ErrorCode.REMOTE_CONTROL_INVALID, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
