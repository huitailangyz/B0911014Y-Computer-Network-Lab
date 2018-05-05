#!/usr/bin/python

import time
from mininet.net import Mininet
from mininet.topo import Topo

class MyTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        self.addLink(h1, h2)

topo = MyTopo()
net = Mininet(topo = topo)

net.start()

h2 = net.get('h2')
h2.cmd('ping -c 3 10.0.0.1 > ping-output.txt &')

time.sleep(5)

net.stop()
