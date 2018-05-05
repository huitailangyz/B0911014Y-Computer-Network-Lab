#!/usr/bin/python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI
import os, time

class MyTopo(Topo):
    def build(self):
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        s1 = self.addSwitch('s1')

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)




#auto make
os.system('mn -c')
os.system('make clean')
if os.system('make') != 0: #if success,return 0
    exit()
print('Compile Success!!!')

print('preparing for mininet...')
topo = MyTopo()
net = Mininet(topo = topo)

print('net start')
net.start()
h1, h2, h3 = net.get('h1', 'h2', 'h3')

print('h2 running')
print h2.cmd('./worker > h2.txt &')
print('h3 running')
print h3.cmd('./worker > h3.txt &')

print('h1 running')
print h1.cmd('./master war_and_peace.txt > h1.txt &')
time.sleep(5)
net.stop()
print('net stop\n')

print('#####################  h1.txt  #####################')
os.system('cat h1.txt')
print('#####################  h2.txt  #####################')
os.system('cat h2.txt')
print('#####################  h3.txt  #####################')
os.system('cat h3.txt')

print('test finish')
