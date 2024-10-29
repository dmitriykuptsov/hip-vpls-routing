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
    "own_ip": "1.1.1.2",
    "own_interface": "r2-eth1",
    "enable_auth": True,
    "routes": {
        "192.168.1.0/24": "r2-tun1",
        "192.168.2.0/24": "r2-tun2",
        "192.168.3.0/24": "r2-tun3"
    },
    "hip": [
        {
            "src": "1.1.1.2",
            "dst": "1.1.1.1",
            "ihit": "2001:0021:b4b6:b7a4:f4cc:0f6b:8779:8ef9",
            "rhit": "2001:0021:efda:99ec:e872:153f:a818:3610"
        },
        {
            "src": "1.1.1.2",
            "dst": "1.1.1.3",
            "ihit": "2001:0021:b4b6:b7a4:f4cc:0f6b:8779:8ef9",
            "rhit": "2001:0021:0093:cbad:9ab7:eed9:c596:af31"
        },
        {
            "src": "1.1.1.2",
            "dst": "1.1.1.4",
            "ihit": "2001:0021:b4b6:b7a4:f4cc:0f6b:8779:8ef9",
            "rhit": "2001:0021:7e43:e8e2:afd2:69fa:833c:cb1f"
        }
    ],
    "interfaces": [
        {
            "name": "r2-tun1",
            "address": "192.168.1.101",
            "mask": "255.255.255.0",
            "destination": "1.1.1.1",
            "auth_key": "RedCivFomcuvDicBagropZothEgyijKo",
            "mtu": 1400
        },
        {
            "name": "r2-tun2",
            "address": "192.168.2.101",
            "mask": "255.255.255.0",
            "destination": "1.1.1.3",
            "auth_key": "JajsegEuctikdydryojrockyotweajCa",
            "mtu": 1400
        },
        {
            "name": "r2-tun3",
            "address": "192.168.3.101",
            "mask": "255.255.255.0",
            "destination": "1.1.1.4",
            "auth_key": "OpEedsEgNovadrovvekawvekyoykAjin",
            "mtu": 1400
        }
    ]
}
