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
from packets import IPv4, GRE
# Sockets
import socket
import traceback
# Utilities
from utils.misc import Misc
# Crypto
from crypto.digest import SHA256HMAC
from crypto.symmetric import AES256CBCCipher
# Logging....
import logging
logger = logging.getLogger("Demultiplexer")
from binascii import unhexlify, hexlify

from os import urandom

AES256_BLOCK_SIZE = 16
SHA256_HMAC_LENGTH = 32
ETHER_HEADER_LENGTH = 14

class Demultiplexer():

    def __init__(self, interfaces, own_ip, own_interface, auth=True):
        self.interfaces = interfaces
        self.routing_table = {}
        self.keys = {}
        self.auth= auth
        self.own_ip = own_ip
        ETH_P_ALL = 3
        #self.socket_in = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.socket_in = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.socket_in.bind((own_interface, 0x0800))
        self.socket_out = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        #self.socket_out.bind((own_ip, 0))
        self.socket_out.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);
        for interface in self.interfaces:
            network = Misc.ipv4_address_to_int(interface["address"]) & Misc.ipv4_address_to_int(interface["mask"])
            self.routing_table[Misc.bytes_to_ipv4_string(Misc.int_to_ipv4_address(network))] = (interface["destination"], interface["auth"]);

        thread = threading.Thread(target=self.read, args=(self.socket_in, self.socket_out), daemon=True)
        thread.start()

    def set_key(self, src, dst, key):
        logger.debug("Setting key for the destination %s " % dst)
        self.keys[dst] = key

    def clear_key(self, src, dst):
        del self.keys[dst]

    def read(self, sock_read, socket_write, mtu = 1500):
        while True:
            try:
                buf = sock_read.recv(mtu)
                outer = IPv4.IPv4Packet(bytearray(buf[ETHER_HEADER_LENGTH:]))

                source = outer.get_source_address()
                destination = outer.get_destination_address()

                gre = GRE.GREPacket(outer.get_payload()[:GRE.GRE_HEADER_LENGTH])

                if Misc.bytes_to_ipv4_string(destination) != self.own_ip:
                    continue
                logging.debug(list(outer.get_payload()[:GRE.GRE_HEADER_LENGTH]))
                logging.debug(list(outer.get_payload()[GRE.GRE_HEADER_LENGTH:]))
                if gre.get_flags() == 0x1:
                    buf = outer.get_payload()[GRE.GRE_HEADER_LENGTH:]
                    icv = buf[-SHA256_HMAC_LENGTH:]
                    buf = buf[:-SHA256_HMAC_LENGTH]
                    key = self.keys.get(Misc.bytes_to_ipv4_string(source), None)
                    if not key:
                        logger.critical("No key was found read_from_public... %s " % Misc.bytes_to_ipv4_string(source))
                        continue
                    sha256 = SHA256HMAC(key[1])
                    hmac = sha256.digest(buf)                    
                    if icv != hmac:
                        logger.critical("Invalid ICV... %s " % hexlify(key[1]))
                        continue
                    inner = IPv4.IPv4Packet(buf)
                else:
                    inner = IPv4.IPv4Packet(outer.get_payload()[GRE.GRE_HEADER_LENGTH:])
                source = inner.get_source_address()
                destination = inner.get_destination_address()
                network = Misc.ipv4_address_to_int(Misc.bytes_to_ipv4_string(destination)) & Misc.ipv4_address_to_int("255.255.255.0")
                
                # Search the routing table entry....
                try:
                    (outer_destination, auth) = self.routing_table[Misc.bytes_to_ipv4_string(Misc.int_to_ipv4_address(network))]
                except:
                    continue

                outer = IPv4.IPv4Packet()
                outer.set_source_address(Misc.ipv4_address_to_bytes(self.own_ip))
                outer.set_destination_address(Misc.ipv4_address_to_bytes(outer_destination))
                outer.set_protocol(GRE.GRE_PROTOCOL_NUMBER)
                outer.set_version(4)
                outer.set_ttl(128)
                outer.set_ihl(5)
                gre = GRE.GREPacket()
                gre.set_protocol(0x0800)
                if auth:
                    key = self.keys.get(outer_destination, None)
                    if not key:
                        logger.critical("No key was found... %s " % outer_destination)
                        continue
                    gre.set_flags(1)
                    data = inner.get_buffer()
                    sha256 = SHA256HMAC(key[1])
                    icv = sha256.digest(data)
                    payload = gre.get_buffer() + data
                    outer.set_payload(payload + icv)
                    outer.set_total_length(len(bytearray(outer.get_buffer())))
                    socket_write.sendto(outer.get_buffer(), (outer_destination, 0))
                else:
                    gre.set_flags(0)
                    data = inner.get_buffer()
                    payload = gre.get_buffer() + data
                    outer.set_payload(payload)
                    outer.set_total_length(len(bytearray(outer.get_buffer())))
                    socket_write.sendto(outer.get_buffer(), (outer_destination, 0))

            except Exception as e:
                logging.debug(traceback.format_exc())
                logging.debug(e)
