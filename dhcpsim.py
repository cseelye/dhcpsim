#!/usr/bin/env python3

# MIT License
#
# Copyright (c) 2018 Carl Seelye
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
from binascii import hexlify, unhexlify
from copy import deepcopy
from enum import Enum
import ipaddress
import logging
import math
import socket
import subprocess

class DhcpReservation(object):
    """A DHCP reservation for a particular MAC address"""

    def __init__(self, inputStr, leaseTime, renewalTime, rebindTime):
        pieces = inputStr.split(":")

        self.options = {}
        self.mac = pieces[0]
        self.ip = pieces[1]
        self.options[DhcpOption.SubnetMask] = pieces[2]
        self.options[DhcpOption.Broadcast] = str(ipaddress.IPv4Network("{}/{}".format(pieces[1], pieces[2]), False).broadcast_address)
        if len(pieces) >= 4:
            self.options[DhcpOption.Router] = pieces[3]
        if len(pieces) >= 5:
            self.options[DhcpOption.DomainServer] = pieces[4]
        if len(pieces) >= 6:
            self.options[DhcpOption.DomainSearch] = pieces[5]

        self.options[DhcpOption.LeaseTime] = leaseTime
        self.options[DhcpOption.RenewTime] = renewalTime
        self.options[DhcpOption.RebindTime] = rebindTime

class DhcpOperation(Enum):
    """DHCP operation code"""
    Request = 1
    Reply = 2

class DhcpMessageType(Enum):
    """DHCP message types"""
    DHCPDISCOVER = 1
    DHCPOFFER = 2
    DHCPREQUEST = 3
    DHCPDECLINE = 4
    DHCPACK = 5
    DHCPNAK = 6
    DHCPRELEASE = 7
    DHCPINFORM = 8

class DhcpOption(Enum):
    """DHCP option IDs"""
    # https://tools.ietf.org/html/rfc2132
    # https://tools.ietf.org/html/rfc3397
    Padding = 0
    SubnetMask = 1
    Router = 3
    DomainServer = 6
    Hostname = 12
    DomainName = 15
    Mtu = 26
    Broadcast = 28
    NtpServer = 42
    AddressRequest = 50
    LeaseTime = 51
    MessageType = 53
    ServerID = 54
    ParameterList = 55
    RenewTime = 58
    RebindTime = 59
    ClientID = 61
    DomainSearch = 119
    End = 255

# Encode/decode functions for each known DHCP option
CODECS = {
    DhcpOption.SubnetMask : {
        "encode_length" : lambda val: b"04",
        "encode_val" : lambda val: hexlify(socket.inet_aton(val)),
        "decode_val" : lambda val: socket.inet_ntoa(val)
    },
    DhcpOption.Router : {
        "encode_length" : lambda val: b"04",
        "encode_val" : lambda val: hexlify(socket.inet_aton(val)),
        "decode_val" : lambda val: socket.inet_ntoa(val)
    },
    DhcpOption.DomainServer : {
        "encode_length" : lambda val: b"04",
        "encode_val" : lambda val: hexlify(socket.inet_aton(val)),
        "decode_val" : lambda val: socket.inet_ntoa(val)
    },
    DhcpOption.Hostname : {
        "encode_length" : lambda val: encode_int_value(round(float(int.bit_length(len(val)))/8)*2),
        "encode_val" : lambda val: hexlify(val.encode("utf-8")),
        "decode_val" : lambda val: val.decode("utf-8")
    },
    DhcpOption.DomainName : {
        "encode_length" : lambda val: encode_int_value(round(float(int.bit_length(len(val)))/8)*2),
        "encode_val" : lambda val: hexlify(val.encode("utf-8")),
        "decode_val" : lambda val: val.decode("utf-8")
    },
    DhcpOption.Mtu : {
        "encode_length" : lambda val: "{:02x}".format(int_byte_count(val)).encode("utf-8"),
        "encode_val" : lambda val: encode_int_value(val),
        "decode_val" : lambda val: int(hexlify(val), 16)
    },
    DhcpOption.Broadcast : {
        "encode_length" : lambda val: b"04",
        "encode_val" : lambda val: hexlify(socket.inet_aton(val)),
        "decode_val" : lambda val: socket.inet_ntoa(val)
    },
    DhcpOption.NtpServer : {
        "encode_length" : lambda val: b"04",
        "encode_val" : lambda val: hexlify(socket.inet_aton(val)),
        "decode_val" : lambda val: socket.inet_ntoa(val)
    },
    DhcpOption.AddressRequest : {
        "encode_length" : lambda val: b"04",
        "encode_val" : lambda val: hexlify(socket.inet_aton(val)),
        "decode_val" : lambda val: socket.inet_ntoa(val)
    },
    DhcpOption.LeaseTime : {
        "encode_length" : lambda val: b"04",
        "encode_val" : lambda val: "{:08x}".format(val).encode("utf-8"),
        "decode_val" : lambda val: int(hexlify(val), 16)
    },
    DhcpOption.MessageType : {
        "encode_length" : lambda val: b"01",
        "encode_val" : lambda val: "{:02x}".format(val.value).encode("utf-8"),
        "decode_val" : lambda val: DhcpMessageType(int(hexlify(val), 16))
    },
    DhcpOption.ServerID : {
        "encode_length" : lambda val: b"04",
        "encode_val" : lambda val: hexlify(socket.inet_aton(val)),
        "decode_val" : lambda val: socket.inet_ntoa(val)
    },
    DhcpOption.ParameterList : {
        "encode_length" : lambda val: encode_int_value(len(val)),
        "encode_val" : lambda val: "".join([encode_int_value(x) for x in val]),
        "decode_val" : lambda val: set(sorted([int(hexlify(val)[idx:idx+2], 16) for idx in range(0, len(val)*2, 2)]))
    },
    DhcpOption.RenewTime : {
        "encode_length" : lambda val: b"04",
        "encode_val" : lambda val: "{:08x}".format(val).encode("utf-8"),
        "decode_val" : lambda val: int(hexlify(val), 16)
    },
    DhcpOption.RebindTime : {
        "encode_length" : lambda val: b"04",
        "encode_val" : lambda val: "{:08x}".format(val).encode("utf-8"),
        "decode_val" : lambda val: int(hexlify(val), 16)
    },
    DhcpOption.ClientID : {
        "encode_length" : lambda val: encode_int_value(round(float(int.bit_length(len(val)))/8)*2),
        "encode_val" : lambda val: hexlify(val.encode("utf-8")),
        "decode_val" : lambda val: val.decode("utf-8")
    },
    DhcpOption.DomainSearch : {
        # TODO - support encoding a list of domain names instead of just a single
        "encode_length" : lambda val: encode_domain_name_len(val),
        "encode_val" : lambda val: encode_domain_name(val),
        "decode_val" : lambda val: val.decode("utf-8")
    },
}

def int_byte_count(val):
    """Get the number of bytes it takes to hold the specified integer"""
    return math.ceil(float(int.bit_length(val))/8)

def encode_int_value(val):
    """Encode an integer"""
    fmt_str = "{{:0{}x}}".format(int_byte_count(val)*2)
    return fmt_str.format(val).encode("utf-8")

def encode_domain_name(strval):
    """Encode a domain name using DNS name compression"""
    # See 4.1.4 of https://tools.ietf.org/html/rfc1035
    encoded = b""
    pieces = strval.split(".")
    for label in pieces:
        encoded += encode_int_value(len(label))
        encoded += hexlify(label.encode("utf-8"))
    encoded += b"00"
    return encoded

def encode_domain_name_len(strval):
    """Encode the length of a domain name that will be encoded with DNS name compression"""
    # See 4.1.4 of https://tools.ietf.org/html/rfc1035
    pieces = strval.split(".")
    length = 0
    for label in pieces:
        length += len(label) + 1
    length += 1
    return encode_int_value(length)

class DhcpPacket(object):
    """DHCP packet"""

    def __init__(self, raw_packet):

        header = raw_packet[0:240]
        dhcp_options = raw_packet[240:]
        logging.debug("incoming header = {}".format(hexlify(header)))
        logging.debug("incoming options = {}".format(hexlify(dhcp_options)))

        # Decode the header
        self.op = int(hexlify(header[0:1]), 16)
        self.htype = int(hexlify(header[1:2]), 16)
        self.hlen = int(hexlify(header[2:3]), 16)
        self.hops = int(hexlify(header[3:4]), 16)
        self.xid = hexlify(header[4:8]).decode("utf-8")
        self.secs = int(hexlify(header[8:10]), 16)
        self.flags = int(hexlify(header[10:12]), 16)
        self.ciaddr = socket.inet_ntoa(header[12:16])
        self.yiaddr = socket.inet_ntoa(header[16:20])
        self.siaddr = socket.inet_ntoa(header[20:24])
        self.giaddr = socket.inet_ntoa(header[24:28])
        self.chaddr = hexlify(header[28:44]).lower().decode("utf-8")
        self.chaddr = self.chaddr[:self.hlen*2]
        self.sname = header[44:108].decode("utf-8")
        self.file = header[108:236].decode("utf-8")
        self.magiccookie = hexlify(header[236:240]).decode("utf-8")

        # Decode the options
        self.options = {}
        idx = 0
        while (idx < len(dhcp_options)):
            opt_id = dhcp_options[idx]
            idx += 1
            opt_len = dhcp_options[idx]
            idx += 1
            opt_raw = dhcp_options[idx:idx+opt_len]
            idx += opt_len

            logging.debug("  opt_id={}, opt_len={}, opt_raw={}".format(opt_id, opt_len, opt_raw))

            try:
                opt_id = DhcpOption(opt_id)
            except ValueError:
                logging.warning("Unknown option {}".format(opt_id))
                continue

            if opt_id == DhcpOption.Padding:
                continue
            if opt_id == DhcpOption.End:
                break

            if opt_id not in CODECS.keys() or "decode_val" not in CODECS[opt_id]:
                logging.warning("No decoder for option {}".format(opt_id))
                continue

            try:
                self.options[opt_id] = CODECS[opt_id]["decode_val"](opt_raw)
            except (ValueError, TypeError, IndexError, AttributeError, OSError) as ex:
                logging.error("Error decoding option {}: {} - {}".format(opt_id.name, type(ex).__name__, ex))
                continue

    def encode(self):
        """Encode this packet for sending over the network"""

        # Encode the header
        data = b""
        data += "{:02x}".format(self.op).encode("utf-8")
        data += "{:02x}".format(self.htype).encode("utf-8")
        data += "{:02x}".format(self.hlen).encode("utf-8")
        data += "{:02x}".format(self.hops).encode("utf-8")
        data += self.xid.encode("utf-8")
        data += "{:04x}".format(self.secs).encode("utf-8")
        data += "{:04x}".format(self.flags).encode("utf-8")
        data += hexlify(socket.inet_aton(self.ciaddr))
        data += hexlify(socket.inet_aton(self.yiaddr))
        data += hexlify(socket.inet_aton(self.siaddr))
        data += hexlify(socket.inet_aton(self.giaddr))
        data += "{:0<32}".format(self.chaddr).encode("utf-8")

        data += ("0"*384).encode("utf-8")
        data += self.magiccookie.encode("utf-8")

        logging.debug("outgoing header = {}".format(data))
        logging.debug("  op     = {}".format(data[0:2]))
        logging.debug("  htype  = {}".format(data[2:4]))
        logging.debug("  hlen   = {}".format(data[4:6]))
        logging.debug("  hops   = {}".format(data[6:8]))
        logging.debug("  xid    = {}".format(data[8:16]))
        logging.debug("  secs   = {}".format(data[16:20]))
        logging.debug("  flags  = {}".format(data[20:24]))
        logging.debug("  ciaddr = {}".format(data[24:32]))
        logging.debug("  yiaddr = {}".format(data[32:40]))
        logging.debug("  siaddr = {}".format(data[40:48]))
        logging.debug("  giaddr = {}".format(data[48:56]))
        logging.debug("  chaddr = {}".format(data[56:88]))
        logging.debug("  magic cookie = {}".format(data[-8:]))

        # Encode the options
        options_data = b""
        for opt, value in self.options.items():
            try:
                opt_encoded = "{:02x}".format(opt.value).encode("utf-8")
                opt_val_encoded = CODECS[opt]["encode_val"](value)
                opt_len_encoded = CODECS[opt]["encode_length"](value)
                logging.debug("  {}={}, len={}, val={}".format(opt.name, opt_encoded[0:2], opt_len_encoded, opt_val_encoded))
                opt_encoded += opt_len_encoded
                opt_encoded += opt_val_encoded
                options_data += opt_encoded
            except (ValueError, TypeError, IndexError, AttributeError, OSError) as ex:
                logging.error("Error encoding option {}: {}".format(opt.name, ex))
                continue

        return unhexlify(data + options_data)

    def offer_response(self, reservation_info, server_ip="0.0.0.0"):
        """Create a DHCPOFFER response based on this packet"""
        packet = deepcopy(self)
        packet.op = DhcpOperation.Reply.value
        packet.yiaddr = reservation_info.ip
        packet.siaddr = server_ip
        packet.options = {}
        packet.options[DhcpOption.ServerID] = server_ip
        packet.options[DhcpOption.MessageType] = DhcpMessageType.DHCPOFFER
        packet.options[DhcpOption.LeaseTime] = 3600
        packet.options[DhcpOption.RenewTime] = 1800
        packet.options[DhcpOption.RebindTime] = 2700
        packet.options[DhcpOption.SubnetMask] = reservation_info.options[DhcpOption.SubnetMask]
        packet.options[DhcpOption.Router] = reservation_info.options[DhcpOption.Router]
        return packet

    def ack_response(self, reservation_info, server_ip="0.0.0.0"):
        """Create a DHCPACK response based on this packet"""
        packet = deepcopy(self)
        packet.op = DhcpOperation.Reply.value
        packet.yiaddr = reservation_info.ip
        packet.siaddr = server_ip
        packet.options = {}
        packet.options[DhcpOption.MessageType] = DhcpMessageType.DHCPACK
        packet.options[DhcpOption.ServerID] = server_ip
        packet.options[DhcpOption.LeaseTime] = 3600
        packet.options[DhcpOption.RenewTime] = 1800
        packet.options[DhcpOption.RebindTime] = 2700
        for opt_id in self.options[DhcpOption.ParameterList]:
            try:
                opt_id = DhcpOption(opt_id)
            except ValueError:
                continue
            opt_val = reservation_info.options.get(opt_id, None)
            if opt_val:
                packet.options[opt_id] = opt_val
        return packet

    def nak_response(self, reservation_info, server_ip="0.0.0.0"):
        """Create a DHCPNAK response based on this packet"""
        packet = deepcopy(self)
        packet.op = DhcpOperation.Reply.value
        packet.yiaddr = "0.0.0.0"
        packet.siaddr = "0.0.0.0"
        packet.options = {}
        packet.options[DhcpOption.MessageType] = DhcpMessageType.DHCPNAK
        packet.options[DhcpOption.ServerID] = server_ip
        return packet

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        all_options = []
        for opt, val in self.options.items():
            all_options.append("{}={}".format(opt.name, val.name if isinstance(val, Enum) else val))

        return "[op={}, hype={}, hlen={}, hops={}, xid={}, secs={}, flags={}, ciaddr={}, yiaddr={}, siaddr={}, giaddr={}, chaddr={}, sname={}, file={}, magiccookie={}, options={{ {} }}]".format(
                self.op,
                self.htype,
                self.hlen,
                self.hops,
                self.xid,
                self.secs,
                self.flags,
                self.ciaddr,
                self.yiaddr,
                self.siaddr,
                self.giaddr,
                self.chaddr,
                self.sname,
                self.file,
                self.magiccookie,
                ",".join(all_options))


class DhcpServer(object):

    def __init__(self, reservations, server_ip=None, port=67):
        self.port = port
        self.reservations = reservations
        self.server_ip = server_ip
        if not self.server_ip:
            self.server_ip = self.get_local_ip()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(('', port))

    def get_local_ip(self):
        retcode, ip = subprocess.getstatusoutput("ifconfig | grep -m1 'inet ' | sed 's/addr://' | grep -v 127.0.0.1 | awk '{print $2}'")
        if retcode != 0:
            ip = "0.0.0.0"
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            ip = "0.0.0.0"
        return ip

    def start(self):
        logging.info("Starting DHCP server")
        while True:
            data = self.sock.recv(4096)
            packet = DhcpPacket(data)
            logging.info("Received {} packet from {} - {}".format(packet.options[DhcpOption.MessageType].name, packet.chaddr, packet))

            if packet.chaddr not in self.reservations:
                logging.warning("No reservation defined for {}, not replying".format(packet.chaddr))
                continue
            client_res = self.reservations[packet.chaddr]
            response = None

            if packet.options[DhcpOption.MessageType] == DhcpMessageType.DHCPDISCOVER:
                response = packet.offer_response(client_res, self.server_ip)

            elif packet.options[DhcpOption.MessageType] == DhcpMessageType.DHCPREQUEST:
                if packet.options.get(DhcpOption.AddressRequest, client_res.ip) == client_res.ip:
                    response = packet.ack_response(client_res, self.server_ip)
                else:
                    logging.error("Requested IP from {} did not match reservation".format(packet.chaddr))
                    response = packet.nak_response(client_res, self.server_ip)

            if response:
                logging.info("Sending {} packet to {} - {}".format(response.options[DhcpOption.MessageType].name, response.chaddr, response))
                self.sock.sendto(response.encode(), ("<broadcast>", 68))
    def stop(self):
        self.sock.close()

def main():
    parser = argparse.ArgumentParser(description="Simulate a DHCP server")
    parser.add_argument("--reservation", "-r", action="append", metavar="MAC:IP:MASK:GATEWAY:DNS:SEARCH", help="Set the DHCP response for the given MAC address")
    parser.add_argument("--lease-time", "-l", default=300, metavar="SECONDS", help="Set the lease time")
    parser.add_argument("--renewal-time", "-w", default=150, metavar="SECONDS", help="Set the renewal time")
    parser.add_argument("--rebind-time", "-b", default=225, metavar="SECONDS", help="Set the rebind time")
    parser.add_argument("--debug", "-d", action="store_true", help="Show more verbose logging")
    args = parser.parse_args()

    if args.debug:
        logging.getlogging().setLevel(logging.DEBUG)

    client_reservations = {}
    if args.reservation:
        for raw_res in args.reservation:
            res = DhcpReservation(raw_res)
            client_reservations[res.mac] = res

    server = DhcpServer(client_reservations)
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()

if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s | %(message)s', datefmt='%m/%d/%Y %H:%M:%S', level=logging.INFO)
    main()
