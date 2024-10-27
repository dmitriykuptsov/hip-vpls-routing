#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, OVSController, OVSKernelSwitch
from mininet.log import setLogLevel, info
from mininet.cli import CLI


class LinuxRouter( Node ):
    "A Node with IP forwarding enabled."

    def config( self, **params ):
        super( LinuxRouter, self).config( **params )
        # Enable forwarding on the router
        self.cmd( 'sysctl net.ipv4.ip_forward=1' )

    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        super( LinuxRouter, self ).terminate()


class NetworkTopo( Topo ):
    def build( self, **_opts ):
        router1 = self.addNode( 'r1', cls=LinuxRouter )
        router2 = self.addNode( 'r2', cls=LinuxRouter )
        router3 = self.addNode( 'r3', cls=LinuxRouter )
        router4 = self.addNode( 'r4', cls=LinuxRouter )
        router5 = self.addNode( 'r5', cls=LinuxRouter )
        router6 = self.addNode( 'r6', cls=LinuxRouter )
        s1, s2, s3, s4 = [ self.addSwitch( s, cls=OVSKernelSwitch ) for s in ( 's1', 's2', 's3', 's4' ) ]
        self.addLink( s4, router1,
                intfName2='r1-eth1',
                params2={ 'ip' : '1.1.1.1/28' } ) # Spoke 1
        self.addLink( s4, router2,
                intfName2='r2-eth1',
                params2={ 'ip' : '1.1.1.2/28' } )
        self.addLink( s4, router3,
                intfName2='r3-eth1',
                params2={ 'ip' : '1.1.1.3/28' } )
        self.addLink( s4, router4,
                intfName2='r4-eth1',
                params2={ 'ip' : '1.1.1.4/28' } )
        self.addLink( s4, router5,
                intfName2='r5-eth1',
                params2={ 'ip' : '1.1.1.5/28' } ) # Spoke 2
        self.addLink( s4, router6,
                intfName2='r6-eth1',
                params2={ 'ip' : '1.1.1.6/28' } ) # Spoke 3
        self.addLink( s1, router1, intfName2='r1-eth0',
                      params2={ 'ip' : '192.168.1.1/24' } )
        self.addLink( s2, router5, intfName2='r5-eth0',
                params2={ 'ip' : '192.168.2.1/24' } )
        self.addLink( s3, router6, intfName2='r6-eth0',
                params2={ 'ip' : '192.168.3.1/24' } )
        h1 = self.addHost( 'h1', ip='192.168.1.100/24',
                           defaultRoute='via 192.168.1.1' )
        h2 = self.addHost( 'h2', ip='192.168.2.100/24',
                           defaultRoute='via 192.168.2.1' )
        h3 = self.addHost( 'h3', ip='192.168.3.100/24',
                           defaultRoute='via 192.168.3.1' )
        for h, s in [ (h1, s1), (h2, s2), (h3, s3) ]:
            self.addLink( h, s )
from time import sleep
def run():
    topo = NetworkTopo()
    net = Mininet(topo=topo, switch=OVSKernelSwitch, controller = OVSController)
    net.start()
    info( net[ 'r1' ].cmd( 'ifconfig r1-eth1 1.1.1.1 netmask 255.255.255.240' ) )
    info( net[ 'r2' ].cmd( 'ifconfig r2-eth1 1.1.1.2 netmask 255.255.255.240' ) )
    info( net[ 'r3' ].cmd( 'ifconfig r3-eth1 1.1.1.3 netmask 255.255.255.240' ) )
    info( net[ 'r4' ].cmd( 'ifconfig r4-eth1 1.1.1.4 netmask 255.255.255.240' ) )
    info( net[ 'r5' ].cmd( 'ifconfig r5-eth1 1.1.1.5 netmask 255.255.255.240' ) )
    info( net[ 'r6' ].cmd( 'ifconfig r6-eth1 1.1.1.6 netmask 255.255.255.240' ) )

    info( net[ 'r1' ].cmd( '/sbin/ethtool -K r1-eth1 rx off tx off sg off' ) )
    info( net[ 'r1' ].cmd( '/sbin/ethtool -K r1-eth0 rx off tx off sg off' ) )
    info( net[ 'r2' ].cmd( '/sbin/ethtool -K r2-eth1 rx off tx off sg off' ) )
    info( net[ 'r3' ].cmd( '/sbin/ethtool -K r3-eth1 rx off tx off sg off' ) )
    info( net[ 'r4' ].cmd( '/sbin/ethtool -K r4-eth1 rx off tx off sg off' ) )
    info( net[ 'r5' ].cmd( '/sbin/ethtool -K r5-eth0 rx off tx off sg off' ) )
    info( net[ 'r5' ].cmd( '/sbin/ethtool -K r5-eth1 rx off tx off sg off' ) )

    info( net[ 'h1' ].cmd( '/sbin/ethtool -K h1-eth0 rx off tx off sg off' ) )
    info( net[ 'h2' ].cmd( '/sbin/ethtool -K h2-eth0 rx off tx off sg off' ) )
    info( net[ 'h3' ].cmd( '/sbin/ethtool -K h2-eth0 rx off tx off sg off' ) )

    info( net[ 'h1' ].cmd( 'ifconfig h1-eth0 mtu 1300' ) )
    info( net[ 'h2' ].cmd( 'ifconfig h2-eth0 mtu 1300' ) )
    info( net[ 'h3' ].cmd( 'ifconfig h3-eth0 mtu 1300' ) )

    info( net[ 's1' ].cmd( 'ovs-vsctl set bridge s1 stp_enable=true' ) )
    info( net[ 's2' ].cmd( 'ovs-vsctl set bridge s2 stp_enable=true' ) )
    info( net[ 's3' ].cmd( 'ovs-vsctl set bridge s3 stp_enable=true' ) )

    info( '*** Routing Table on Router:\n' )
    info( net[ 'r1' ].cmd( 'route' ) )
    info( '*** Routing Table on Router:\n' )
    info( net[ 'r2' ].cmd( 'route' ) )
    info( '*** Running L3-VPN on router 1 *** \n')
    info( net[ 'r1' ].cmd( 'cd spoke-router-1 && python3 router.py  > /dev/null&' ) )
    info( '*** Running L3-VPN on router 2 *** \n')
    info( net[ 'r2' ].cmd( 'cd core-router-1 && python3 router.py  > /dev/null&' ) )
    info( '*** Running L3-VPN on router 3 *** \n')
    info( net[ 'r3' ].cmd( 'cd core-router-2 && python3 router.py  > /dev/null&' ) )
    info( '*** Running L3-VPN on router 4 *** \n')
    info( net[ 'r4' ].cmd( 'cd core-router-3 && python3 router.py  > /dev/null&' ) )
    info( '*** Running L3-VPN on router 5 *** \n')
    info( net[ 'r5' ].cmd( 'cd spoke-router-2 && python3 router.py  > /dev/null&' ) )
    info( '*** Running L3-VPN on router 6 *** \n')
    info( net[ 'r6' ].cmd( 'cd spoke-router-3 && python3 router.py  > /dev/null&' ) )

    sleep(10)
    info( net[ 'r2' ].cmd( 'ip addr' ) )
    
    info( net[ 'r2' ].cmd( 'ip route add 192.168.1.0/24 dev r2-tun1' ) )
    info( net[ 'r2' ].cmd( 'ip route add 192.168.2.0/24 dev r2-tun2' ) )
    info( net[ 'r2' ].cmd( 'ip route add 192.168.3.0/24 dev r2-tun3' ) )

    info( net[ 'r3' ].cmd( 'ip route add 192.168.2.0/24 dev r3-tun1' ) )
    info( net[ 'r3' ].cmd( 'ip route add 192.168.1.0/24 dev r3-tun2' ) )
    info( net[ 'r3' ].cmd( 'ip route add 192.168.3.0/24 dev r3-tun3' ) )

    info( net[ 'r4' ].cmd( 'ip route add 192.168.3.0/24 dev r4-tun1' ) )
    info( net[ 'r4' ].cmd( 'ip route add 192.168.1.0/24 dev r4-tun2' ) )
    info( net[ 'r4' ].cmd( 'ip route add 192.168.2.0/24 dev r4-tun3' ) )

    info( net[ 'r5' ].cmd( 'ip route add default dev r5-tun1' ) )
    info( net[ 'r1' ].cmd( 'ip route add default dev r1-tun1' ) )
    info( net[ 'r6' ].cmd( 'ip route add default dev r6-tun1' ) )
    
    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    run()