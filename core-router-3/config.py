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
    "own_ip": "1.1.1.4",
    "own_interface": "r4-eth1",
    "hip": [
        {
            "src": "1.1.1.4",
            "dst": "1.1.1.6",
            "ihit": "2001:0021:7e43:e8e2:afd2:69fa:833c:cb1f",
            "rhit": "2001:0021:d666:2c04:242f:e2b4:cbe7:b3b3"
        },
        {
            "src": "1.1.1.4",
            "dst": "1.1.1.7",
            "ihit": "2001:0021:7e43:e8e2:afd2:69fa:833c:cb1f",
            "rhit": "2001:0021:032b:595c:cee0:1b09:20ea:0ead"
        },
    ],
    "interfaces": [
        {
            "address": "192.168.3.0",
            "mask": "255.255.255.0",
            "destination": "1.1.1.6",
            "mtu": 1400,
            "auth": True
        },
        {

            "name": "r4-tun2",
            "address": "192.168.1.0",
            "mask": "255.255.255.0",
            "destination": "1.1.1.2",
            "mtu": 1400,
            "auth": False
        }, 
        {
            "address": "192.168.2.0",
            "mask": "255.255.255.0",
            "destination": "1.1.1.3",
            "mtu": 1400,
            "auth": False
        },
        {
            "address": "192.168.4.0",
            "mask": "255.255.255.0",
            "destination": "1.1.1.7",
            "mtu": 1400,
            "auth": True
        }
    ]
}
