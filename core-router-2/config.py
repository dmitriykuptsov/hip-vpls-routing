#!/usr/bin/python

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

config = {
    "own_ip": "1.1.1.3",
    "own_interface": "r3-eth1",
    "hip": [
        {
            "src": "1.1.1.3",
            "dst": "1.1.1.5",
            "ihit": "2001:0021:0093:cbad:9ab7:eed9:c596:af31",
            "rhit": "2001:0021:012c:ea2f:7f84:8bdc:fcbf:d22c"
        }
    ],
    "interfaces": [
        {
            "address": "192.168.2.0",
            "mask": "255.255.255.0",
            "destination": "1.1.1.5",
            "mtu": 1400,
            "auth": True
        },
        {
            "address": "192.168.1.0",
            "mask": "255.255.255.0",
            "destination": "1.1.1.2",
            "mtu": 1400,
            "auth": False
        }, 
        {
            "address": "192.168.3.0",
            "mask": "255.255.255.0",
            "destination": "1.1.1.4",
            "mtu": 1400,
            "auth": False
        },
        {
            "address": "192.168.4.0",
            "mask": "255.255.255.0",
            "destination": "1.1.1.4",
            "mtu": 1400,
            "auth": False
        }
    ]
}
