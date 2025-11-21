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

__author__ = "Dmitriy Kuptsov"
__copyright__ = "Copyright 2024, strangebit"
__license__ = "GPL"
__version__ = "0.0.1b"
__maintainer__ = "Dmitriy Kuptsov"
__email__ = "dmitriy.kuptsov@strangebit.io"
__status__ = "development"

# Sleep
from time import sleep
# Configuration
from config import config
# Main router functionality
from demultiplexer.demux import Demultiplexer
# HIP Server
import crypto_server
from hiplib.utils.misc import Utils
# Logging....
import logging
logger = logging.getLogger("router")
# Hexidecimal utlis
from binascii import hexlify

demux = None
cs = None
def completed_callback(cipher, hmac, cipher_key, hmac_key, src, dst):
    global demux
    src_str = Utils.ipv4_bytes_to_string(src)
    dst_str = Utils.ipv4_bytes_to_string(dst)
    if demux:
        logger.debug("src=%s, dst=%s, key=%s" % (src_str, dst_str, hexlify(hmac_key)))
        demux.set_key(src_str, dst_str, (cipher_key, hmac_key))

def closed_callback(ihit, rhit, src, dst):
    global demux
    global cs
    src_str = Utils.ipv4_bytes_to_string(src)
    dst_str = Utils.ipv4_bytes_to_string(dst)
    if demux:
        try:
            demux.clear_key(src_str, dst_str)
        except:
            pass
    if cs:
        try:
            cs.trigger_bex(ihit, 
                       rhit, 
                       src_str, 
                       dst_str)
        except Exception as e:
            logger.critical("Exception occured in triggering BEX")
            logger.critical(e)

# Host Identity Protocol crypto server
# Performs BEX and derives the keys to secure 
# The dataplane
cs = crypto_server.CryptoServer(completed_callback, closed_callback)
demux = Demultiplexer(config["interfaces"], 
                      config["own_ip"], 
                      config["own_interface"])

for peer in config["hip"]:
    cs.trigger_bex(Utils.hex_formatted_to_ipv6_bytes(peer["ihit"]), 
                   Utils.hex_formatted_to_ipv6_bytes(peer["rhit"]), 
                   peer["src"], 
                   peer["dst"])

while True:
    print("Periodic task....")
    sleep(10)