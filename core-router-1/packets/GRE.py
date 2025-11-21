#!/usr/bin/python3

# Copyright (C) 2019 strangebit

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
import logging

import copy

PROTOCOL_OFFSET                   = 0x2;
PROTOCOL_LENGTH                   = 0x2;

FLAGS_OFFSET                      = 0x1;

GRE_PROTOCOL_NUMBER               = 0x2F;

GRE_HEADER_LENGTH                 = 0x4;

class GREPacket():
    def __init__(self, buffer = None):
        if buffer:
            self.buffer = buffer;
        else:
            self.buffer = bytearray([0] * GRE_HEADER_LENGTH);
    def get_protocol(self):
        buf = self.buffer[PROTOCOL_OFFSET:PROTOCOL_OFFSET + 1];
        return ((buf[0] << 8) & 0xFF00 | buf[1] & 0xFF)
    def set_protocol(self, protocol):
        self.buffer[PROTOCOL_OFFSET] = (protocol >> 0x8) & 0xFF;
        self.buffer[PROTOCOL_OFFSET + 1] = protocol & 0xFF;
    def get_flags(self):
        return (self.buffer[FLAGS_OFFSET] >> 3) & 0xFF;
    def set_flags(self, flags):
        self.buffer[FLAGS_OFFSET] = flags << 3;
    def get_buffer(self):
        return self.buffer[:GRE_HEADER_LENGTH];