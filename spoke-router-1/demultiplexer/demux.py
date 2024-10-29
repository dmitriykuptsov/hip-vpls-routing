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
        self.public_ip = public_ip
        self.private_ip = private_ip
        self.hub_ip = hub_ip
        self.auth = auth
        self.key = None

        tunif = tun.Tun(address=private_ip, mtu=1500, name=private_interface);
        self.socket_public = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.socket_public.bind((public_interface, 0x0800))

        self.socket_raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.socket_raw.bind((public_ip, 0))
        self.socket_raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);

        thread = threading.Thread(target=self.read_from_public, args=(self.socket_public, tunif, self.private_ip, ), daemon=True)
        thread.start()

        thread = threading.Thread(target=self.read_from_private, args=(self.socket_raw, tunif, self.public_ip, self.hub_ip), daemon=True)
        thread.start()
    

    def set_key(self, key):
        self.key = key

    def clear_key(self):
        self.key = None

    def read_from_public(self, pubfd, privfd, private_ip, mtu=1500):
        while True:
            try:
                buf = pubfd.recv(mtu)
                logging.debug("read_from_public")
                logging.debug(list(buf))
                outer = IPv4.IPv4Packet(bytearray(buf[ETHER_HEADER_LENGTH:]))

                source = outer.get_source_address()
                destination = outer.get_destination_address()

                if Misc.bytes_to_ipv4_string(destination) != self.public_ip:
                    continue

                if self.auth:
                    buf = outer.get_payload()                    
                    icv = buf[-SHA256_HMAC_LENGTH:]
                    buf = buf[:-SHA256_HMAC_LENGTH]
                    
                    if not self.key:
                        logger.critical("No key was found read_from_public... %s " % Misc.bytes_to_ipv4_string(source))
                        continue

                    iv = buf[:AES256_BLOCK_SIZE]
                    data = buf[AES256_BLOCK_SIZE:]
                    aes = AES256CBCCipher()

                    payload = aes.decrypt(self.key[0], iv, data)

                    sha256 = SHA256HMAC(self.key[1])
                    hmac = sha256.digest(payload)
                    
                    if icv != hmac:
                        logger.critical("Invalid ICV... %s " % hexlify(self.key[0]))
                        continue
                    inner = IPv4.IPv4Packet(payload)
                else:
                    inner = IPv4.IPv4Packet(outer.get_payload())                
                privfd.write(inner.get_buffer())
            except Exception as e:
                logging.debug("read from public")
                logging.critical(traceback.format_exc())
                logging.critical(e)

    def read_from_private(self, pubfd, privfd, public_ip, hub_ip, mtu=1500):
        while True:
            try:
                buf = privfd.read(mtu)
                inner = IPv4.IPv4Packet(buf)
                outer = IPv4.IPv4Packet()
                outer.set_destination_address(Misc.ipv4_address_to_bytes(hub_ip))
                outer.set_source_address(Misc.ipv4_address_to_bytes(public_ip))
                outer.set_protocol(4)
                outer.set_ttl(128)
                outer.set_ihl(5)
                if self.auth:                    
                    if not self.key:
                        logger.critical("No key was found...")
                        continue
                    sha256 = SHA256HMAC(self.key[1])
                    logging.debug(list(self.key[0]))
                    logging.debug(list(self.key[1]))
                    icv = sha256.digest(buf)
                    iv = urandom(AES256_BLOCK_SIZE)
                    data = buf
                    aes = AES256CBCCipher()
                    payload = iv + aes.encrypt(self.key[0], iv, data)
                    outer.set_payload(payload + icv)
                    logging.debug("read_from_private")
                    logging.debug(list(payload + icv))
                    outer.set_total_length(len(bytearray(outer.get_buffer())))
                    pubfd.sendto(outer.get_buffer(), (hub_ip, 0))
                else:
                    pubfd.sendto(outer.get_buffer(), (hub_ip, 0))
            except Exception as e:
                logging.debug("read from private")
                logging.critical(traceback.format_exc())
                logging.critical(e)

   

        
