import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tunpcap  # noqa: E402


def pcap_header(linktype: int) -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)


class BuildArgsTest(unittest.TestCase):
    def test_build_start_args_joins_apps_and_omits_default_name(self):
        args = tunpcap.build_start_args(["a.b", "c.d"], None)
        self.assertEqual(
            args[:3], ["am", "start", "-n"]
        )
        self.assertEqual(args[3], "dev.plat1ko.tunpcap/.CaptureCtrl")
        i = args.index("app_filter")
        self.assertEqual(args[i - 1], "--es")
        self.assertEqual(args[i + 1], "a.b,c.d")
        for key, value in [("action", "start"), ("pcap_dump_mode", "pcap_file")]:
            self.assertEqual(args[args.index(key) + 1], value)
        self.assertEqual(args[args.index("full_payload") - 1], "--ez")
        self.assertNotIn("pcap_name", args)

    def test_build_start_args_with_name(self):
        args = tunpcap.build_start_args(["a.b"], "x.pcap")
        self.assertEqual(args[-3:], ["--es", "pcap_name", "x.pcap"])

    def test_build_stop_args(self):
        self.assertEqual(
            tunpcap.build_stop_args(),
            ["am", "start", "-n", "dev.plat1ko.tunpcap/.CaptureCtrl", "--es", "action", "stop"],
        )


class VpnActiveTest(unittest.TestCase):
    def test_vpn_active_matches_session(self):
        text = "NetworkAgentInfo{... VpnTransportInfo{type=1, sessionId=TunPcap, bypassable=false} ...}"
        self.assertTrue(tunpcap.vpn_active(text))

    def test_vpn_active_ignores_other_vpn(self):
        self.assertFalse(tunpcap.vpn_active("VpnTransportInfo{type=1, sessionId=PCAPdroid}"))
        self.assertFalse(tunpcap.vpn_active("VpnTransportInfo{type=1, sessionId=Clash}"))
        self.assertFalse(tunpcap.vpn_active(""))


class PcapHeaderTest(unittest.TestCase):
    def test_check_pcap_header_raw(self):
        self.assertEqual(tunpcap.check_pcap_header(pcap_header(101)), 101)

    def test_check_pcap_header_rejects_sll(self):
        with self.assertRaises(ValueError):
            tunpcap.check_pcap_header(pcap_header(113))

    def test_check_pcap_header_rejects_short(self):
        with self.assertRaises(ValueError):
            tunpcap.check_pcap_header(b"\xd4\xc3\xb2\xa1" + b"\x00" * 6)

    def test_check_pcap_header_rejects_bad_magic(self):
        with self.assertRaises(ValueError):
            tunpcap.check_pcap_header(b"\x00" * 20 + struct.pack("<I", 101))


if __name__ == "__main__":
    unittest.main()
