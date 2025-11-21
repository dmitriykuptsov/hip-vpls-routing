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
from packets import IPv4, Ethernet, GRE
# Sockets
import socket
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

import traceback

AES256_BLOCK_SIZE = 16
SHA256_HMAC_LENGTH = 32
ETHER_HEADER_LENGTH = 14

class Demultiplexer():

    def __init__(self, public_ip, private_ip, hub_ip, public_interface, private_interface, auth=False):
        self.auth = auth
        
        socket_public = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
        socket_public.bind((public_interface, 0x0800))

        socket_private = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
        socket_private.bind((private_interface, 0x0800))

        socket_raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        socket_raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);

        thread = threading.Thread(target=self.read_from_public, args=(socket_public, socket_raw, ), daemon=True)
        thread.start()

        thread = threading.Thread(target=self.read_from_private, args=(socket_raw, socket_private, public_ip, hub_ip), daemon=True)
        thread.start()
    

    def set_key(self, key):
        self.key = key

    def clear_key(self):
        self.key = None

    def read_from_public(self, pubfd, privfd, mtu=1500):
        while True:
            try:
                buf = pubfd.recv(mtu)
                logging.debug("read_from_public")
                logging.debug(list(buf))
                outer = IPv4.IPv4Packet(bytearray(buf[ETHER_HEADER_LENGTH:]))

                source = outer.get_source_address()
                destination = outer.get_destination_address()

                logging.debug("Source %s" % Misc.bytes_to_ipv4_string(source))
                logging.debug("Destination %s" % Misc.bytes_to_ipv4_string(destination))

                if Misc.bytes_to_ipv4_string(destination) != self.public_ip:
                    continue
                gre = GRE.GREPacket(outer.get_payload()[:GRE.GRE_HEADER_LENGTH])
                if gre.get_flags() == 0x1:
                    buf = outer.get_payload()
                    icv = buf[-SHA256_HMAC_LENGTH:]
                    buf = buf[GRE.GRE_HEADER_LENGTH:-SHA256_HMAC_LENGTH]
                    
                    if not self.key:
                        logger.critical("No key was found read_from_public... %s " % Misc.bytes_to_ipv4_string(source))
                        continue
                    payload = buf
                    sha256 = SHA256HMAC(self.key[1])
                    hmac = sha256.digest(payload)
                    if icv != hmac:
                        logger.critical("Invalid ICV... %s " % hexlify(self.key[0]))
                        continue
                    inner = IPv4.IPv4Packet(payload)
                else:
                    inner = IPv4.IPv4Packet(outer.get_payload()[GRE.GRE_HEADER_LENGTH:])
                
                destination = inner.get_destination_address()
                privfd.send(inner.get_buffer(), (destination, 0))
            except Exception as e:
                logging.critical(traceback.format_exc())
                logging.critical(e)

    def read_from_private(self, pubfd, privfd, public_ip, hub_ip, mtu=1500):
        while True:
            try:
                buf = privfd.recv(mtu)
                inner = IPv4.IPv4Packet(buf)
                outer = IPv4.IPv4Packet()
                outer.set_destination_address(Misc.ipv4_address_to_bytes(hub_ip))
                outer.set_source_address(Misc.ipv4_address_to_bytes(public_ip))
                outer.set_protocol(GRE.GRE_PROTOCOL_NUMBER)
                outer.set_version(4)
                outer.set_ttl(128)
                outer.set_ihl(5)

                data = buf

                gre = GRE.GREPacket()
                gre.set_protocol(0x0800)

                if self.auth:                    
                    if not self.key:
                        logger.critical("No key was found...")
                        continue
                    sha256 = SHA256HMAC(self.key[1])
                    icv = sha256.digest(buf)
                    gre.set_flags(1)
                    payload = gre.get_buffer() + data
                    outer.set_payload(payload + icv)
                    outer.set_total_length(len(bytearray(outer.get_buffer())))
                    pubfd.sendto(outer.get_buffer(), (hub_ip, 0))
                else:
                    gre.set_flags(0)
                    payload = gre.get_buffer() + data
                    outer.set_payload(payload)
                    pubfd.sendto(outer.get_buffer(), (hub_ip, 0))
            except Exception as e:
                logging.debug("read from private")
                logging.critical(traceback.format_exc())
                logging.critical(e)

   

        
