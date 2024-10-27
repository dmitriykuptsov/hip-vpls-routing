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

demux = None
cs = None
def completed_callback(cipher, hmac, cipher_key, hmac_key, src, dst):
    global demux
    if demux:
        demux.set_key(hmac_key)

def closed_callback(ihit, rhit, src, dst):
    global demux
    global cs
    if demux:
        demux.clear_key()
    if cs:
        cs.trigger_bex(ihit, rhit, src, dst)

# Host Identity Protocol crypto server
# Performs BEX and derives the keys to secure 
# The dataplane
cs = crypto_server.CryptoServer(completed_callback, closed_callback)
demux = Demultiplexer(config["public_ip"], config["private_ip"], config["hub_ip"], config["auth_key"], config["enable_auth"])

while True:
    print("Periodic task....")
    sleep(10)