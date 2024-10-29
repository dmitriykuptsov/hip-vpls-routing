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
from packets import IPv4
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
        self.demux_table = {}
        self.keys = {}
        self.auth= auth
        self.own_ip = own_ip
        self.tuns = []
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.socket.bind((own_interface, 0x0800))
        self.socket_raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.socket_raw.bind((own_ip, 0))
        self.socket_raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);
        for interface in self.interfaces:
            tunif = tun.Tun(address=interface["address"], mtu=interface["mtu"], name=interface["name"]);
            network = Misc.ipv4_address_to_int(interface["address"]) & Misc.ipv4_address_to_int(interface["mask"])
            self.demux_table[Misc.bytes_to_ipv4_string(Misc.int_to_ipv4_address(network))] = tunif;
            thread = threading.Thread(target=self.read_from_tun, args=(tunif, self.socket_raw, interface["destination"], interface["mtu"]), daemon=True)
            thread.start()

        thread = threading.Thread(target=self.read_from_public, args=(self.socket, ), daemon=True)
        thread.start()

    def set_key(self, src, dst, key):
        logger.debug("Setting key for the destination %s " % dst)
        self.keys[dst] = key

    def clear_key(self, src, dst):
        del self.keys[dst]

    def read_from_public(self, sockfd, mtu = 1500):
        while True:
            try:
                buf = sockfd.recv(mtu)
                outer = IPv4.IPv4Packet(bytearray(buf[ETHER_HEADER_LENGTH:]))

                source = outer.get_source_address()
                destination = outer.get_destination_address()

                if Misc.bytes_to_ipv4_string(destination) != self.own_ip:
                    continue
                if self.auth:
                    buf = outer.get_payload()
                    logging.debug("read_from_public")
                    logging.debug(list(buf))
                    icv = buf[-SHA256_HMAC_LENGTH:]
                    buf = buf[:-SHA256_HMAC_LENGTH]
                    key = self.keys.get(Misc.bytes_to_ipv4_string(source), None)
                    if not key:
                        logger.critical("No key was found read_from_public... %s " % Misc.bytes_to_ipv4_string(source))
                        continue

                    iv = buf[:AES256_BLOCK_SIZE]
                    data = buf[AES256_BLOCK_SIZE:]
                    aes = AES256CBCCipher()
                    logging.debug(len(data))
                    payload = aes.decrypt(key[0], iv, data)
                    logging.debug(list(key[0]))
                    logging.debug(list(key[1]))
                    sha256 = SHA256HMAC(key[1])
                    hmac = sha256.digest(payload)
                    
                    if icv != hmac:
                        logger.critical("Invalid ICV... %s " % hexlify(key[1]))
                        continue
                    inner = IPv4.IPv4Packet(payload)
                else:
                    inner = IPv4.IPv4Packet(outer.get_payload())
                source = inner.get_source_address()
                destination = inner.get_destination_address()
                network = Misc.ipv4_address_to_int(Misc.bytes_to_ipv4_string(destination)) & Misc.ipv4_address_to_int("255.255.255.0")
                tun = self.demux_table[Misc.bytes_to_ipv4_string(Misc.int_to_ipv4_address(network))]
                tun.write(inner.get_buffer())
            except Exception as e:
                logging.debug(traceback.format_exc())
                logging.debug(e)

    
    def read_from_tun(self, tunfd, sockfd, destination, mtu = 1500):
        while True:
            try:
                buf = tunfd.read(mtu);
                inner = IPv4.IPv4Packet(bytearray(buf))
                outer = IPv4.IPv4Packet()
                outer.set_source_address(Misc.ipv4_address_to_bytes(self.own_ip))
                outer.set_destination_address(Misc.ipv4_address_to_bytes(destination))
                outer.set_protocol(4)
                outer.set_ttl(128)
                outer.set_ihl(5)
                if self.auth:
                    key = self.keys.get(destination, None)
                    if not key:
                        logger.critical("No key was found... %s " % destination)
                        continue
                    sha256 = SHA256HMAC(key[1])
                    icv = sha256.digest(buf)
                    iv = urandom(AES256_BLOCK_SIZE)
                    data = buf
                    aes = AES256CBCCipher()
                    payload = iv + aes.encrypt(key[0], iv, data)
                    logging.debug("read_from_tun")
                    outer.set_payload(payload + icv)
                    outer.set_total_length(len(bytearray(outer.get_buffer())))
                    sockfd.sendto(outer.get_buffer(), (destination, 0))
                else:
                    sockfd.sendto(outer.get_buffer(), (destination, 0))
            except Exception as e:
                logging.debug(traceback.format_exc())
                logging.debug(e)
        
