#!/usr/bin/python3

# Copyright (C) 2024 strangebit
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Threading
import threading
# Tunneling interfaces
from networking import tun
# IPv4 packet structure
from packets import IPv4, Ethernet
# Sockets
import socket
# Utilities
from utils.misc import Misc
# Crypto
from crypto.digest import SHA256HMAC

class Demultiplexer():

    def __init__(self, public_ip, private_ip, hub_ip, key = None, auth=False):
        self.public_ip = public_ip
        self.private_ip = private_ip
        self.hub_ip = hub_ip
        self.auth = auth
        self.key = bytearray(key.encode("ascii"))

        demux_tun = tun.Tun(address="192.168.2.2", mtu=1500, name="r5-tun1");
        self.socket_public = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.socket_public.bind(("r5-eth1", 0x0800))

        self.socket_raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.socket_raw.bind((public_ip, 0))
        self.socket_raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);

        thread = threading.Thread(target=self.read_from_public, args=(self.socket_public, demux_tun, self.private_ip, ), daemon=True)
        thread.start()

        thread = threading.Thread(target=self.read_from_private, args=(self.socket_raw, demux_tun, self.public_ip, self.hub_ip), daemon=True)
        thread.start()
    
    def read_from_public(self, pubfd, privfd, private_ip, mtu=1500):
        while True:
            try:
                buf = pubfd.recv(mtu)
                if self.auth:
                    outer = IPv4.IPv4Packet(buf[14:-32])
                else:
                    outer = IPv4.IPv4Packet(buf[14:])
                destination = outer.get_destination_address()
                if Misc.bytes_to_ipv4_string(destination) != self.public_ip:
                    continue
                if self.auth:
                    icv = buf[-32:]
                    sha256 = SHA256HMAC(self.key)
                    hmac = sha256.digest(outer.get_payload())
                    if icv != hmac:
                        continue
                inner = outer.get_payload()
                privfd.write(inner)
            except Exception as e:
                print(e)

    def read_from_private(self, pubfd, privfd, public_ip, hub_ip, mtu=1500):
        while True:
            try:
                buf = privfd.read(mtu)
                inner = IPv4.IPv4Packet(buf)
                packet = IPv4.IPv4Packet()
                packet.set_destination_address(Misc.ipv4_address_to_bytes(hub_ip))
                packet.set_source_address(Misc.ipv4_address_to_bytes(public_ip))
                packet.set_protocol(4)
                packet.set_ttl(128)
                packet.set_payload(inner.get_buffer())
                packet.set_ihl(5)
                packet.set_total_length(len(packet.get_buffer()))
                if self.auth:                   
                    sha256 = SHA256HMAC(self.key)
                    hmac = sha256.digest(packet.get_payload())
                    pubfd.sendto(packet.get_buffer() + hmac, (hub_ip, 0))
                else:
                    pubfd.sendto(packet.get_buffer(), (hub_ip, 0))                
            except Exception as e:
                print(e)

   

        
