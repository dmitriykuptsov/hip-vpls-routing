#!/usr/bin/python3

# Copyright (C) 2022 strangebit

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
__copyright__ = "Copyright 2022, strangebit"
__license__ = "GPL"
__version__ = "0.0.1b"
__maintainer__ = "Dmitriy Kuptsov"
__email__ = "dmitriy.kuptsov@strangebit.io"
__status__ = "development"

# Import the needed libraries
# OS library
import os
# Stacktrace
import traceback
# Sockets
import socket
# Threading
import threading
# Logging
import logging
from logging.handlers import RotatingFileHandler
# Timing
import time
# Math functions
from math import ceil, floor
# System
import sys
# Exit handler
import atexit
# Timing 
from time import sleep
from time import time

# Hex
from binascii import hexlify

# Import HIP library
from hiplib import hlib

# Utilities
from hiplib.utils import misc

# Crypto stuff
from hiplib.crypto import digest

from hiplib.hlib import HIPLib

# HIP related packets
from hiplib.packets import HIP
# IPSec packets
from hiplib.packets import IPSec
# IPv6 packets
from hiplib.packets import IPv6
# IPv4 packets 
from hiplib.packets import IPv4
# Ethernet frame
from hiplib.packets import Ethernet
# Controller packets
from hiplib.packets import Controller
# Configuration
from hiplib.config import config as hip_config
# Import switch FIB

# Network stuff
import socket

# Copy routines
import copy

# Configure logging to console and file
logging.basicConfig(
    level=logging.CRITICAL,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("hip.log")#,
        #logging.StreamHandler(sys.stdout)
    ]
);

class CryptoServer():
    def __init__(self, completed, closed):
        self.hiplib = HIPLib(hip_config.config, completed, closed);
        self.hip_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, HIP.HIP_PROTOCOL);
        self.hip_socket.bind(("0.0.0.0", HIP.HIP_PROTOCOL));
        self.hip_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);
        self.hip_th_loop = threading.Thread(target = self.hip_loop, args = (), daemon = True);
        logging.info("Starting the HIPv2");
        self.hip_th_loop.start();
        self.main_th_loop = threading.Thread(target = self.maintenance, args = (), daemon = True);
        logging.info("Starting the HIPv2");
        self.main_th_loop.start();
    
    def trigger_bex(self, ihit, rhit, src_str, dst_str):
        try:
            (hip, packet, dest) = self.hiplib.trigger_bex(ihit, rhit, src_str, dst_str)    
            if hip:
                self.hip_socket.sendto(packet, dest)
        except Exception as e:
           logging.debug("Exception occured while trigger BEX")
           logging.debug(e)


    def maintenance(self):
        while True:
            try:
                packets = self.hiplib.maintenance();
                for (packet, dest) in packets:
                    self.hip_socket.sendto(packet, dest)
                logging.debug("...Periodic cleaning task...")
                sleep(1);
            except Exception as e:
                logging.critical("Exception occured while processing HIP packets in maintenance loop")
                logging.critical(e);
                sleep(1)

    def hip_loop(self):
        while True:
            try:
                packet = bytearray(self.hip_socket.recv(1518))
                logging.debug("Got HIP packet on the interface")
                packets = self.hiplib.process_hip_packet(packet);
                for (packet, dest) in packets:
                    self.hip_socket.sendto(packet, dest)
            except Exception as e:
                logging.debug("Exception occured while processing HIP packet")
                logging.debug(e)
                logging.debug(traceback.format_exc())
