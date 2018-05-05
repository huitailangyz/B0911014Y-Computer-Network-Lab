#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI

class RouterTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')

        r1 = self.addHost('r1')
        r2 = self.addHost('r2')
        r3 = self.addHost('r3')
        r4 = self.addHost('r4')
        
        self.addLink(h1, r1)
        self.addLink(h2, r1)
        self.addLink(h3, r2)
        self.addLink(h4, r2)
        self.addLink(h5, r3)
        self.addLink(h6, r3)
        self.addLink(r1, r4)
        self.addLink(r2, r4)
        self.addLink(r3, r4)

if __name__ == '__main__':
    topo = RouterTopo()
    net = Mininet(topo = topo, controller = None) 

    h1, h2, h3, h4, h5, h6, r1, r2, r3, r4 = net.get('h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'r1', 'r2', 'r3', 'r4')
    h1.cmd('ifconfig h1-eth0 10.0.1.11/24')
    h2.cmd('ifconfig h2-eth0 10.0.2.22/24')
    h3.cmd('ifconfig h3-eth0 10.0.3.33/24')
    h4.cmd('ifconfig h4-eth0 10.0.4.44/24')
    h5.cmd('ifconfig h5-eth0 10.0.5.55/24')
    h6.cmd('ifconfig h6-eth0 10.0.6.66/24')

    h1.cmd('route add default gw 10.0.1.1')
    h2.cmd('route add default gw 10.0.2.1')
    h3.cmd('route add default gw 10.0.3.1')
    h4.cmd('route add default gw 10.0.4.1')
    h5.cmd('route add default gw 10.0.5.1')
    h6.cmd('route add default gw 10.0.6.1')

    for h in (h1, h2, h3, h4, h5, h6):
        h.cmd('./scripts/disable_offloading.sh')
        h.cmd('./scripts/disable_ipv6.sh')

    
    r1.cmd('ifconfig r1-eth0 10.0.1.1/24')
    r1.cmd('ifconfig r1-eth1 10.0.2.1/24')
    r1.cmd('ifconfig r1-eth2 10.0.7.1/24')
    r1.cmd('route add default gw 10.0.7.2')

    r2.cmd('ifconfig r2-eth0 10.0.3.1/24')
    r2.cmd('ifconfig r2-eth1 10.0.4.1/24')
    r2.cmd('ifconfig r2-eth2 10.0.8.1/24')
    r2.cmd('route add default gw 10.0.8.2')

    r3.cmd('ifconfig r3-eth0 10.0.5.1/24')
    r3.cmd('ifconfig r3-eth1 10.0.6.1/24')
    r3.cmd('ifconfig r3-eth2 10.0.9.1/24')
    r3.cmd('route add default gw 10.0.9.2')

    r4.cmd('ifconfig r4-eth0 10.0.7.2/24')
    r4.cmd('ifconfig r4-eth1 10.0.8.2/24')
    r4.cmd('ifconfig r4-eth2 10.0.9.2/24')
    r4.cmd('route add -net 10.0.1.0/24 gw 10.0.7.1')
    r4.cmd('route add -net 10.0.2.0/24 gw 10.0.7.1')
    r4.cmd('route add -net 10.0.3.0/24 gw 10.0.8.1')
    r4.cmd('route add -net 10.0.4.0/24 gw 10.0.8.1')
    r4.cmd('route add -net 10.0.5.0/24 gw 10.0.9.1')
    r4.cmd('route add -net 10.0.6.0/24 gw 10.0.9.1')


    for r in (r1, r2, r3, r4):
        r.cmd('./scripts/disable_arp.sh')
        r.cmd('./scripts/disable_icmp.sh')
        r.cmd('./scripts/disable_ip_forward.sh')

    net.start()
    CLI(net)
    net.stop()
