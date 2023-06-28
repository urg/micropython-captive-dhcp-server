import unittest
import struct
from ..packet import Header, Ip, DhcpOptions, DhcpMessageType, DhcpOffer


class TestHeader(unittest.TestCase):
    # Thanks to https://github.com/lvfrazao/dhcppython/blob/master/tests/test_packet.py
    discover_android = (
        b"\x01\x01\x06\x00\xea\xbe"
        b"\xc3\x97\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x8c\x45\x00\x1d\x48\x16\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x63\x82\x53\x63\x35\x01\x01\x3d\x07\x01"
        b"\x8c\x45\x00\x1d\x48\x16\x39\x02\x05\xdc\x3c\x0e\x61\x6e\x64\x72"
        b"\x6f\x69\x64\x2d\x64\x68\x63\x70\x2d\x39\x0c\x09\x47\x61\x6c\x61"
        b"\x78\x79\x2d\x53\x39\x37\x0a\x01\x03\x06\x0f\x1a\x1c\x33\x3a\x3b"
        b"\x2b\xff"
    )
    request_android = [
        0x01,
        0x01,
        0x06,
        0x00,
        0xEA,
        0xBE,
        0xC3,
        0x97,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x8C,
        0x45,
        0x00,
        0x1D,
        0x48,
        0x16,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x63,
        0x82,
        0x53,
        0x63,
        0x35,
        0x01,
        0x03,
        0x3D,
        0x07,
        0x01,
        0x8C,
        0x45,
        0x00,
        0x1D,
        0x48,
        0x16,
        0x32,
        0x04,
        0xC0,
        0xA8,
        0x01,
        0xA6,
        0x36,
        0x04,
        0xC0,
        0xA8,
        0x01,
        0xFE,
        0x39,
        0x02,
        0x05,
        0xDC,
        0x3C,
        0x0E,
        0x61,
        0x6E,
        0x64,
        0x72,
        0x6F,
        0x69,
        0x64,
        0x2D,
        0x64,
        0x68,
        0x63,
        0x70,
        0x2D,
        0x39,
        0x0C,
        0x09,
        0x47,
        0x61,
        0x6C,
        0x61,
        0x78,
        0x79,
        0x2D,
        0x53,
        0x39,
        0x37,
        0x0A,
        0x01,
        0x03,
        0x06,
        0x0F,
        0x1A,
        0x1C,
        0x33,
        0x3A,
        0x3B,
        0x2B,
        0xFF,
    ]
    request_android_bytes: bytes = struct.pack(
        ">" + len(request_android) * "B", *request_android
    )
    discover_linux = (
        b"\x01\x01\x06\x00\x2e\xf9"
        b"\x31\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x08\x00\x27\x92\x1f\xae\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x63\x82\x53\x63\x35\x01\x01\x32\x04\xc0"
        b"\xa8\x38\x03\x0c\x05\x6d\x61\x72\x69\x6f\x37\x0d\x01\x1c\x02\x03"
        b"\x0f\x06\x77\x0c\x2c\x2f\x1a\x79\x2a\xff\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00"
    ).strip(b"\x00")
    offer_linux = (
        b"\x02\x01\x06\x00\x2e\xf9"
        b"\x31\x7f\x00\x00\x00\x00\x00\x00\x00\x00\xc0\xa8\x38\x03\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x08\x00\x27\x92\x1f\xae\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x63\x82\x53\x63\x01\x04\xff\xff\xff\x00"
        b"\x03\x04\x0a\x97\x01\x01\x06\x04\x0a\x68\x01\x08\x0c\x09\x6d\x61"
        b"\x72\x69\x6f\x2e\x63\x6f\x6d\x0f\x0e\x73\x77\x65\x65\x74\x77\x61"
        b"\x74\x65\x72\x2e\x63\x6f\x6d\x33\x04\x00\x01\x51\x80\x35\x01\x02"
        b"\x36\x04\xc0\xa8\x38\x02\x3a\x04\x00\x00\x54\x60\x3b\x04\x00\x00"
        b"\xa8\xc0\xff"
    ).strip(b"\x00")
    request_linux = (
        b"\x01\x01\x06\x00\x2e\xf9"
        b"\x31\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x08\x00\x27\x92\x1f\xae\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x63\x82\x53\x63\x35\x01\x03\x36\x04\xc0"
        b"\xa8\x38\x02\x32\x04\xc0\xa8\x38\x03\x0c\x05\x6d\x61\x72\x69\x6f"
        b"\x37\x0d\x01\x1c\x02\x03\x0f\x06\x77\x0c\x2c\x2f\x1a\x79\x2a\xff"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00"
    ).strip(b"\x00")
    ack_linux = (
        b"\x02\x01\x06\x00\x2e\xf9"
        b"\x31\x7f\x00\x00\x00\x00\x00\x00\x00\x00\xc0\xa8\x38\x03\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x08\x00\x27\x92\x1f\xae\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x63\x82\x53\x63\x01\x04\xff\xff\xff\x00"
        b"\x03\x04\x0a\x97\x01\x01\x06\x04\x0a\x68\x01\x08\x0c\x09\x6d\x61"
        b"\x72\x69\x6f\x2e\x63\x6f\x6d\x0f\x0e\x73\x77\x65\x65\x74\x77\x61"
        b"\x74\x65\x72\x2e\x63\x6f\x6d\x33\x04\x00\x01\x51\x80\x35\x01\x05"
        b"\x36\x04\xc0\xa8\x38\x02\x3a\x04\x00\x00\x54\x60\x3b\x04\x00\x00"
        b"\xa8\xc0\xff"
    ).strip(b"\x00")
    rouge = (
        b"\x01\x01\x06\x00d\x9b\x03c\x00\x01\x80\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xcc\xf4\x11g\x8a\xa7"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00gwifi_rouge_dhcp_detection"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00c\x82Sc5\x01\x01\xff"
    )

    def test_rouge(self):
        packet = Header.parse(self.rouge)
        print(packet)

    def test_header(self):
        header = Header()
        header.unpack(self.discover_android)

        # print(header)

        self.assertEqual(header.op, 1)
        self.assertEqual(header.htype, 1)
        self.assertEqual(header.hlen, 6)
        self.assertEqual(header.hops, 0)
        self.assertEqual(header.xid, 0xEABEC397)
        self.assertEqual(header.secs, 1)
        self.assertEqual(header.flags, 0)
        self.assertEqual(header.magic, 0x63825363)
        self.assertEqual(
            header.options[DhcpOptions.DHCP_MESSAGE_TYPE], DhcpMessageType.DISCOVER
        )
        self.assertEqual(header.options[DhcpOptions.MAX_MESSAGE_SIZE], 1500)
        self.assertEqual(header.options[DhcpOptions.VENDOR_CLASS_ID], "android-dhcp-9")
        self.assertEqual(header.options[DhcpOptions.HOST_NAME], "Galaxy-S9")
        self.assertEqual(
            header.options[DhcpOptions.PARAM_REQUEST_LIST], "1,3,6,15,26,28,51,58,59,43"
        )

        self.assertEqual(header.pack(), self.discover_android)

    def test_discover(self):
        packet = Header.parse(self.discover_linux)
        # print(packet)

        self.assertEqual(packet.header.op, 1)
        self.assertEqual(packet.header.htype, 1)
        self.assertEqual(packet.header.hlen, 6)
        self.assertEqual(packet.header.hops, 0)
        self.assertEqual(packet.header.xid, 0x2EF9317F)
        self.assertEqual(packet.header.secs, 0)
        self.assertEqual(packet.header.flags, 0)
        self.assertEqual(packet.header.magic, 0x63825363)

        self.assertEqual(
            packet.header.options[DhcpOptions.DHCP_MESSAGE_TYPE],
            DhcpMessageType.DISCOVER,
        )
        self.assertEqual(
            Ip.int_to_str(packet.header.options[DhcpOptions.REQUESTED_IP]),
            "192.168.56.3",
        )
        self.assertEqual(packet.header.options[DhcpOptions.HOST_NAME], "mario")
        self.assertEqual(
            packet.header.options[DhcpOptions.PARAM_REQUEST_LIST],
            "1,28,2,3,15,6,119,12,44,47,26,121,42",
        )

        self.assertEqual(packet.pack(), self.discover_linux)

    def test_offer(self):
        packet = Header.parse(self.offer_linux)
        print(packet)

        self.assertEqual(packet.header.op, 2)
        self.assertEqual(packet.header.htype, 1)
        self.assertEqual(packet.header.hlen, 6)
        self.assertEqual(packet.header.hops, 0)
        self.assertEqual(packet.header.xid, 0x2EF9317F)
        self.assertEqual(packet.header.secs, 0)
        self.assertEqual(packet.header.flags, 0)
        self.assertEqual(packet.header.magic, 0x63825363)

        self.assertEqual(Ip.int_to_str(packet.header.yiaddr), "192.168.56.3")

        self.assertEqual(
            packet.header.options[DhcpOptions.DHCP_MESSAGE_TYPE], DhcpMessageType.OFFER
        )
        self.assertEqual(
            Ip.int_to_str(packet.header.options[DhcpOptions.SUBNET]), "255.255.255.0"
        )
        self.assertEqual(
            Ip.int_to_str(packet.header.options[DhcpOptions.ROUTER]), "10.151.1.1"
        )
        self.assertEqual(
            Ip.int_to_str(packet.header.options[DhcpOptions.DNS]), "10.104.1.8"
        )
        self.assertEqual(
            Ip.int_to_str(packet.header.options[DhcpOptions.DHCP_SERVER]),
            "192.168.56.2",
        )
        self.assertEqual(packet.header.options[DhcpOptions.HOST_NAME], "mario.com")
        self.assertEqual(
            packet.header.options[DhcpOptions.DOMAIN_NAME], "sweetwater.com"
        )
        self.assertEqual(packet.header.options[DhcpOptions.LEASE_TIME], 86400)
        self.assertEqual(packet.header.options[DhcpOptions.RENEWAL_T1], 21600)
        self.assertEqual(packet.header.options[DhcpOptions.RENEWAL_T2], 43200)

        self.assertEqual(packet.pack(), self.offer_linux)

    def test_offer_answer(self):
        discover = Header.parse(self.discover_linux)
        offer = DhcpOffer()
        offer.answer(discover, "192.168.4.250", "192.168.4.1", "255.255.255.0")

        self.assertEqual(offer.header.xid, discover.header.xid)
        self.assertEqual(offer.header.chaddr1, discover.header.chaddr1)
        self.assertEqual(offer.header.chaddr2, discover.header.chaddr2)
        self.assertEqual(offer.header.chaddr3, discover.header.chaddr3)
        self.assertEqual(offer.header.chaddr4, discover.header.chaddr4)

        self.assertEqual(Ip.int_to_str(offer.header.yiaddr), "192.168.4.250")

        self.assertEqual(
            Ip.int_to_str(offer.header.options[DhcpOptions.DHCP_SERVER]), "192.168.4.1"
        )
        self.assertEqual(
            Ip.int_to_str(offer.header.options[DhcpOptions.ROUTER]), "192.168.4.1"
        )
        self.assertEqual(
            Ip.int_to_str(offer.header.options[DhcpOptions.DNS]), "192.168.4.1"
        )
        self.assertEqual(Ip.int_to_str(offer.header.siaddr), "192.168.4.1")

        self.assertEqual(
            Ip.int_to_str(offer.header.options[DhcpOptions.SUBNET]), "255.255.255.0"
        )
        self.assertEqual(offer.header.options[DhcpOptions.LEASE_TIME], 86400)

    def test_request(self):
        packet = Header.parse(self.request_linux)
        # print(packet)

        self.assertEqual(packet.header.op, 1)
        self.assertEqual(packet.header.htype, 1)
        self.assertEqual(packet.header.hlen, 6)
        self.assertEqual(packet.header.hops, 0)
        self.assertEqual(packet.header.xid, 0x2EF9317F)
        self.assertEqual(packet.header.secs, 0)
        self.assertEqual(packet.header.flags, 0)
        self.assertEqual(packet.header.magic, 0x63825363)

        self.assertEqual(
            packet.header.options[DhcpOptions.DHCP_MESSAGE_TYPE],
            DhcpMessageType.REQUEST,
        )
        self.assertEqual(
            Ip.int_to_str(packet.header.options[DhcpOptions.REQUESTED_IP]),
            "192.168.56.3",
        )
        self.assertEqual(
            Ip.int_to_str(packet.header.options[DhcpOptions.DHCP_SERVER]),
            "192.168.56.2",
        )
        self.assertEqual(packet.header.options[DhcpOptions.HOST_NAME], "mario")
        self.assertEqual(
            packet.header.options[DhcpOptions.PARAM_REQUEST_LIST],
            "1,28,2,3,15,6,119,12,44,47,26,121,42",
        )

        self.assertEqual(packet.pack(), self.request_linux)

    def test_ack(self):
        packet = Header.parse(self.ack_linux)
        # print(packet)

        self.assertEqual(packet.header.op, 2)
        self.assertEqual(packet.header.htype, 1)
        self.assertEqual(packet.header.hlen, 6)
        self.assertEqual(packet.header.hops, 0)
        self.assertEqual(packet.header.xid, 0x2EF9317F)
        self.assertEqual(packet.header.secs, 0)
        self.assertEqual(packet.header.flags, 0)
        self.assertEqual(packet.header.magic, 0x63825363)

        self.assertEqual(Ip.int_to_str(packet.header.yiaddr), "192.168.56.3")

        self.assertEqual(
            packet.header.options[DhcpOptions.DHCP_MESSAGE_TYPE], DhcpMessageType.ACK
        )
        self.assertEqual(
            Ip.int_to_str(packet.header.options[DhcpOptions.SUBNET]), "255.255.255.0"
        )
        self.assertEqual(
            Ip.int_to_str(packet.header.options[DhcpOptions.ROUTER]), "10.151.1.1"
        )
        self.assertEqual(
            Ip.int_to_str(packet.header.options[DhcpOptions.DNS]), "10.104.1.8"
        )
        self.assertEqual(packet.header.options[DhcpOptions.HOST_NAME], "mario.com")
        self.assertEqual(
            packet.header.options[DhcpOptions.DOMAIN_NAME], "sweetwater.com"
        )
        self.assertEqual(packet.header.options[DhcpOptions.LEASE_TIME], 86400)
        self.assertEqual(
            Ip.int_to_str(packet.header.options[DhcpOptions.DHCP_SERVER]),
            "192.168.56.2",
        )
        self.assertEqual(packet.header.options[DhcpOptions.RENEWAL_T1], 21600)
        self.assertEqual(packet.header.options[DhcpOptions.RENEWAL_T2], 43200)

        self.assertEqual(packet.pack(), self.ack_linux)

    def test_ip(self):
        self.assertEqual("192.168.1.5", Ip.next_ip("192.168.1.4"))


if __name__ == "__main__":
    unittest.main()
