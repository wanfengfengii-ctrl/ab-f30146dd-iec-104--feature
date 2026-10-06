"""Type 45（C_SC_NA_1）遥控选择/执行/终止证据链的单元测试。"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

from protocol import AuditError, ErrorCode, audit_request  # noqa: E402

STARTDT_ACT = "680407000000"
STARTDT_CON = "68040b000000"
STOPDT_ACT = "680413000000"
STOPDT_CON = "680423000000"

PLAIN_ASDU = b"\x01\x04\x03\x00\x00\x00"


def i_frame(send: int, recv: int, asdu: bytes = PLAIN_ASDU) -> str:
    body = bytes(
        [(send << 1) & 0xFF, (send << 1) >> 8,
         (recv << 1) & 0xFF, (recv << 1) >> 8]
    ) + asdu
    return (bytes([0x68, len(body)]) + body).hex()


def s_frame(recv: int) -> str:
    body = bytes([0x01, 0x00, (recv << 1) & 0xFF, (recv << 1) >> 8])
    return (bytes([0x68, 4]) + body).hex()


def rc_asdu(
    cot: int,
    *,
    ca: int = 1,
    ioa: int = 101,
    qos: int = 0x01,
    pn: bool = False,
    vsq: int = 0x01,
    extra: bytes = b"",
) -> bytes:
    """构造 C_SC_NA_1（Type 45）ASDU：默认单对象、10 字节。"""
    return bytes(
        [
            45,
            vsq,
            (cot & 0x3F) | (0x40 if pn else 0),
            0,
            ca & 0xFF,
            ca >> 8,
            ioa & 0xFF,
            (ioa >> 8) & 0xFF,
            (ioa >> 16) & 0xFF,
            qos,
        ]
    ) + extra


def rc_frame(send: int, recv: int, cot: int, *, pn: bool = False, **kw) -> str:
    return i_frame(send, recv, rc_asdu(cot, pn=pn, **kw))


def f(direction: str, apdu: str, ts: int) -> dict:
    return {"direction": direction, "apdu": apdu, "capturedAtUs": ts}


def started(ts0: int = 10):
    return [f("client", STARTDT_ACT, ts0), f("server", STARTDT_CON, ts0 + 1)]


def full_op(i_send=0, s_send=0, recv=0, ioa=101, ca=1, t0=100):
    """一条完整合法的选择-执行-终止链，返回 (帧列表, 下一组发送/确认序号)。"""
    frames = [
        f("client", rc_frame(i_send, recv, 6, ioa=ioa, ca=ca, qos=0x81), t0),
        f("server", rc_frame(s_send, i_send + 1, 7, ioa=ioa, ca=ca, qos=0x81), t0 + 1),
        f("client", rc_frame(i_send + 1, s_send + 1, 6, ioa=ioa, ca=ca, qos=0x01), t0 + 2),
        f("server", rc_frame(s_send + 1, i_send + 2, 7, ioa=ioa, ca=ca, qos=0x01), t0 + 3),
        f("server", rc_frame(s_send + 2, i_send + 2, 10, ioa=ioa, ca=ca, qos=0x01), t0 + 4),
    ]
    return frames, i_send + 2, s_send + 3


class RemoteControlHappyPathTests(unittest.TestCase):
    def audit_rc(self, frames, delay=1_000_000, window=32):
        return audit_request(
            {
                "maxWindow": window,
                "remoteControl": {"maxSelectDelayUs": delay},
                "frames": frames,
            }
        )

    def test_single_completed_operation(self):
        frames = started()
        op, _, _ = full_op()
        frames += op
        result = self.audit_rc(frames)["result"]
        self.assertEqual(result["remoteControl"], {"completed": 1, "rejected": 0})

    def test_two_completed_operations_same_object(self):
        frames = started()
        op1, i_s, s_s = full_op(t0=100)
        op2, _, _ = full_op(i_send=i_s, s_send=s_s, recv=i_s, t0=200)
        frames += op1 + op2
        result = self.audit_rc(frames)["result"]
        self.assertEqual(result["remoteControl"], {"completed": 2, "rejected": 0})

    def test_negative_select_confirmation_counts_rejected(self):
        # 负确认结束操作、计为 rejected；该对象之后可以重新发起并完成。
        frames = started() + [
            f("client", rc_frame(0, 0, 6, qos=0x81), 100),
            f("server", rc_frame(0, 1, 7, qos=0x81, pn=True), 101),
            f("client", rc_frame(1, 1, 6, qos=0x81), 102),
            f("server", rc_frame(1, 2, 7, qos=0x81), 103),
            f("client", rc_frame(2, 2, 6, qos=0x01), 104),
            f("server", rc_frame(2, 3, 7, qos=0x01), 105),
            f("server", rc_frame(3, 3, 10, qos=0x01), 106),
        ]
        result = self.audit_rc(frames)["result"]
        self.assertEqual(result["remoteControl"], {"completed": 1, "rejected": 1})

    def test_negative_execution_confirmation_counts_rejected(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 6, qos=0x81), 100),
            f("server", rc_frame(0, 1, 7, qos=0x81), 101),
            f("client", rc_frame(1, 1, 6, qos=0x01), 102),
            f("server", rc_frame(1, 2, 7, qos=0x01, pn=True), 103),
        ]
        result = self.audit_rc(frames)["result"]
        self.assertEqual(result["remoteControl"], {"completed": 0, "rejected": 1})

    def test_different_objects_interleave(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 6, ioa=101, qos=0x81), 100),
            f("client", rc_frame(1, 0, 6, ioa=102, qos=0x81), 101),
            f("server", rc_frame(0, 2, 7, ioa=102, qos=0x81), 102),
            f("server", rc_frame(1, 2, 7, ioa=101, qos=0x81), 103),
            f("client", rc_frame(2, 2, 6, ioa=101, qos=0x01), 104),
            f("server", rc_frame(2, 3, 7, ioa=101, qos=0x01), 105),
            f("server", rc_frame(3, 3, 10, ioa=101, qos=0x01), 106),
            f("client", rc_frame(3, 4, 6, ioa=102, qos=0x01), 107),
            f("server", rc_frame(4, 4, 7, ioa=102, qos=0x01), 108),
            f("server", rc_frame(5, 4, 10, ioa=102, qos=0x01), 109),
            f("client", s_frame(6), 110),
        ]
        result = self.audit_rc(frames)["result"]
        self.assertEqual(result["remoteControl"], {"completed": 2, "rejected": 0})

    def test_select_delay_boundary_is_inclusive(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 6, qos=0x81), 100),
            f("server", rc_frame(0, 1, 7, qos=0x81), 101),
            f("client", rc_frame(1, 1, 6, qos=0x01), 100_100),  # 恰好 100000μs
            f("server", rc_frame(1, 2, 7, qos=0x01), 100_101),
            f("server", rc_frame(2, 2, 10, qos=0x01), 100_102),
        ]
        result = self.audit_rc(frames, delay=100_000)["result"]
        self.assertEqual(result["remoteControl"], {"completed": 1, "rejected": 0})

    def test_non_type45_iframes_are_ignored_by_rc_tracker(self):
        # 数据传送阶段的普通 I 帧不参与遥控裁决。
        frames = started() + [
            f("client", i_frame(0, 0), 100),
            f("server", i_frame(0, 1), 101),
            f("client", s_frame(1), 102),
        ]
        result = self.audit_rc(frames)["result"]
        self.assertEqual(result["remoteControl"], {"completed": 0, "rejected": 0})

    def test_large_common_and_information_addresses(self):
        ca, ioa = 65535, 0xFFFFFF
        frames = started()
        op, _, _ = full_op(ca=ca, ioa=ioa)
        result = self.audit_rc(frames + op)["result"]
        self.assertEqual(result["remoteControl"], {"completed": 1, "rejected": 0})

    def test_disabled_feature_keeps_original_contract(self):
        # 省略 remoteControl 时 Type 45 帧与普通 I 帧无异，结果不含新字段。
        frames = started() + [f("client", rc_frame(0, 0, 6, qos=0x81), 100)]
        result = audit_request({"maxWindow": 12, "frames": frames})["result"]
        self.assertNotIn("remoteControl", result)

        # 空对象或不含 maxSelectDelayUs 同样不启用。
        result = audit_request(
            {"maxWindow": 12, "remoteControl": {}, "frames": frames}
        )["result"]
        self.assertNotIn("remoteControl", result)


class RemoteControlRejectionTests(unittest.TestCase):
    def expect_error(self, frames, index, delay=1_000_000):
        try:
            audit_request(
                {
                    "maxWindow": 32,
                    "remoteControl": {"maxSelectDelayUs": delay},
                    "frames": frames,
                }
            )
        except AuditError as exc:
            self.assertIs(exc.code, ErrorCode.REMOTE_CONTROL_REJECTED)
            self.assertEqual(exc.frame_index, index, exc.message)
            self.assertNotIn("后续", exc.message)
            return exc
        raise AssertionError("应当抛出 REMOTE_CONTROL_REJECTED")

    def test_execute_without_select(self):
        frames = started() + [f("client", rc_frame(0, 0, 6, qos=0x01), 100)]
        self.expect_error(frames, 2)

    def test_execute_without_select_confirmation(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 6, qos=0x81), 100),
            f("client", rc_frame(1, 0, 6, qos=0x01), 101),
        ]
        self.expect_error(frames, 3)

    def test_select_confirmation_without_select(self):
        frames = started() + [
            f("server", rc_frame(0, 0, 7, qos=0x81), 100),
        ]
        self.expect_error(frames, 2)

    def test_termination_without_execution_chain(self):
        frames = started() + [
            f("server", rc_frame(0, 0, 10, qos=0x01), 100),
        ]
        self.expect_error(frames, 2)

    def test_missing_select_confirmation_dangling_points_at_select(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 6, qos=0x81), 100),
        ]
        self.expect_error(frames, 2)

    def test_missing_execution_dangling_points_at_select(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 6, qos=0x81), 100),
            f("server", rc_frame(0, 1, 7, qos=0x81), 101),
        ]
        self.expect_error(frames, 2)

    def test_missing_execution_confirmation_dangling_points_at_select(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 6, qos=0x81), 100),
            f("server", rc_frame(0, 1, 7, qos=0x81), 101),
            f("client", rc_frame(1, 1, 6, qos=0x01), 102),
        ]
        self.expect_error(frames, 2)

    def test_missing_termination_dangling_points_at_select(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 6, qos=0x81), 100),
            f("server", rc_frame(0, 1, 7, qos=0x81), 101),
            f("client", rc_frame(1, 1, 6, qos=0x01), 102),
            f("server", rc_frame(1, 2, 7, qos=0x01), 103),
        ]
        self.expect_error(frames, 2)

    def test_select_execution_timeout_points_at_select(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 6, qos=0x81), 100),
            f("server", rc_frame(0, 1, 7, qos=0x81), 101),
            f("client", rc_frame(1, 1, 6, qos=0x01), 200_101),
        ]
        self.expect_error(frames, 2, delay=200_000)

    def test_select_confirmation_after_timeout_but_exec_in_window_still_fails(self):
        # 时限度量选择激活->执行激活；超时后即使链路完整也必须拒绝。
        frames = started() + [
            f("client", rc_frame(0, 0, 6, qos=0x81), 100),
            f("server", rc_frame(0, 1, 7, qos=0x81), 300_001),
            f("client", rc_frame(1, 1, 6, qos=0x01), 300_002),
            f("server", rc_frame(1, 2, 7, qos=0x01), 300_003),
            f("server", rc_frame(2, 2, 10, qos=0x01), 300_004),
        ]
        self.expect_error(frames, 2, delay=200_000)

    def test_qualifier_mismatch_on_select_confirmation(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 6, qos=0x81), 100),
            f("server", rc_frame(0, 1, 7, qos=0x82), 101),
        ]
        self.expect_error(frames, 3)

    def test_qualifier_mismatch_on_execution_confirmation(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 6, qos=0x81), 100),
            f("server", rc_frame(0, 1, 7, qos=0x81), 101),
            f("client", rc_frame(1, 1, 6, qos=0x01), 102),
            f("server", rc_frame(1, 2, 7, qos=0x00), 103),
        ]
        self.expect_error(frames, 5)

    def test_qualifier_mismatch_on_termination(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 6, qos=0x81), 100),
            f("server", rc_frame(0, 1, 7, qos=0x81), 101),
            f("client", rc_frame(1, 1, 6, qos=0x01), 102),
            f("server", rc_frame(1, 2, 7, qos=0x01), 103),
            f("server", rc_frame(2, 2, 10, qos=0x02), 104),
        ]
        self.expect_error(frames, 6)

    def test_common_address_mismatch(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 6, ca=1, ioa=101, qos=0x81), 100),
            f("server", rc_frame(0, 1, 7, ca=2, ioa=101, qos=0x81), 101),
        ]
        self.expect_error(frames, 3)

    def test_information_object_address_mismatch(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 6, ioa=101, qos=0x81), 100),
            f("server", rc_frame(0, 1, 7, ioa=202, qos=0x81), 101),
        ]
        self.expect_error(frames, 3)

    def test_same_object_reentry_while_open(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 6, ioa=101, qos=0x81), 100),
            f("client", rc_frame(1, 0, 6, ioa=101, qos=0x81), 101),
        ]
        self.expect_error(frames, 3)

    def test_same_object_reentry_after_positive_select_confirmation(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 6, ioa=101, qos=0x81), 100),
            f("server", rc_frame(0, 1, 7, ioa=101, qos=0x81), 101),
            f("client", rc_frame(1, 1, 6, ioa=101, qos=0x81), 102),
        ]
        self.expect_error(frames, 4)

    def test_master_sends_activation_confirmation_cot(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 7, qos=0x81), 100),
        ]
        self.expect_error(frames, 2)

    def test_master_sends_termination_cot(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 10, qos=0x01), 100),
        ]
        self.expect_error(frames, 2)

    def test_server_sends_activation_cot(self):
        frames = started() + [
            f("server", rc_frame(0, 0, 6, qos=0x81), 100),
        ]
        self.expect_error(frames, 2)

    def test_unknown_cot_rejected(self):
        frames = started() + [
            f("server", rc_frame(0, 0, 44), 100),
        ]
        self.expect_error(frames, 2)

    def test_negative_bit_on_master_frame(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 6, qos=0x81, pn=True), 100),
        ]
        self.expect_error(frames, 2)

    def test_negative_bit_on_termination(self):
        frames = started() + [
            f("client", rc_frame(0, 0, 6, qos=0x81), 100),
            f("server", rc_frame(0, 1, 7, qos=0x81), 101),
            f("client", rc_frame(1, 1, 6, qos=0x01), 102),
            f("server", rc_frame(1, 2, 7, qos=0x01), 103),
            f("server", rc_frame(2, 2, 10, qos=0x01, pn=True), 104),
        ]
        self.expect_error(frames, 6)

    def test_multi_object_vsq_rejected(self):
        apdu = rc_asdu(6, qos=0x81, vsq=0x02, extra=b"\x00\x00\x00\x01")
        frames = started() + [f("client", i_frame(0, 0, apdu), 100)]
        self.expect_error(frames, 2)

    def test_truncated_type45_asdu_rejected(self):
        apdu = rc_asdu(6, qos=0x81)[:9]
        frames = started() + [f("client", i_frame(0, 0, apdu), 100)]
        self.expect_error(frames, 2)

    def test_negative_confirmation_with_mismatched_qualifier_rejected(self):
        # 负确认同样必须与激活的限定词对应，不对应属于字段不匹配。
        frames = started() + [
            f("client", rc_frame(0, 0, 6, qos=0x81), 100),
            f("server", rc_frame(0, 1, 7, qos=0x82, pn=True), 101),
        ]
        self.expect_error(frames, 3)

    def test_termination_after_execution_negative_confirm_rejected(self):
        # 执行负确认已结束操作；之后的终止无操作可匹配。
        frames = started() + [
            f("client", rc_frame(0, 0, 6, qos=0x81), 100),
            f("server", rc_frame(0, 1, 7, qos=0x81), 101),
            f("client", rc_frame(1, 1, 6, qos=0x01), 102),
            f("server", rc_frame(1, 2, 7, qos=0x01, pn=True), 103),
            f("server", rc_frame(2, 2, 10, qos=0x01), 104),
        ]
        self.expect_error(frames, 6)


class RemoteControlRequestValidationTests(unittest.TestCase):
    def test_delay_bounds(self):
        body = {"frames": started(), "maxWindow": 12}
        for bad in (0, -1, 60_000_001, 1.5, "1000", True, None):
            body_copy = dict(body)
            body_copy["remoteControl"] = {"maxSelectDelayUs": bad}
            with self.assertRaises(AuditError) as cm:
                audit_request(body_copy)
            self.assertIs(cm.exception.code, ErrorCode.INVALID_REQUEST)

    def test_delay_boundary_values_accepted(self):
        frames = started()
        for good in (1, 60_000_000):
            audit_request(
                {
                    "maxWindow": 12,
                    "remoteControl": {"maxSelectDelayUs": good},
                    "frames": frames,
                }
            )

    def test_remote_control_must_be_object(self):
        with self.assertRaises(AuditError) as cm:
            audit_request(
                {
                    "maxWindow": 12,
                    "remoteControl": [],
                    "frames": started(),
                }
            )
        self.assertIs(cm.exception.code, ErrorCode.INVALID_REQUEST)

    def test_timestamps_required_when_enabled(self):
        body = {
            "maxWindow": 12,
            "remoteControl": {"maxSelectDelayUs": 1000},
            "frames": [
                {"direction": "client", "apdu": STARTDT_ACT},
                {"direction": "server", "apdu": STARTDT_CON, "capturedAtUs": 2},
            ],
        }
        try:
            audit_request(body)
        except AuditError as exc:
            self.assertIs(exc.code, ErrorCode.INVALID_REQUEST)
            self.assertEqual(exc.frame_index, 0)
        else:
            self.fail("缺少 capturedAtUs 应当拒绝")


if __name__ == "__main__":
    unittest.main(verbosity=2)
