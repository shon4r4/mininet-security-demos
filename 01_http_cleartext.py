#!/usr/bin/env python3
"""
01_http_cleartext.py
- Topology: h1 -- s1 -- h3 (plus h2 unused)
- Starts a simple HTTP server on h3
- Sends a form POST from h1 to h3
- Captures on s1-eth3 to /tmp/http_cleartext.pcap
- Saves client output to /tmp/http_post.txt
"""
import os, time, subprocess, signal
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel

PCAP = "/tmp/http_cleartext.pcap"

def start_tcpdump(iface, pcap):
    cmd = f"tcpdump -i {iface} -w {pcap} -U -s 0 not arp"
    return subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    setLogLevel('info')
    net = Mininet(controller=Controller, switch=OVSSwitch, link=TCLink, autoSetMacs=True, build=False)

    c0 = net.addController('c0')
    s1 = net.addSwitch('s1')
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')

    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.build(); c0.start(); s1.start([c0])

    # Capture on the h3 side of the switch
    dump = start_tcpdump("s1-eth3", PCAP)
    time.sleep(1)

    # Start HTTP server on h3
    h3.cmd("nohup python3 -m http.server 80 > /tmp/http_server.log 2>&1 &")
    time.sleep(1)

    # Issue POST from h1
    out = h1.cmd('curl -i -X POST -d "username=alice&password=secret123" http://10.0.0.3/login')
    with open("/tmp/http_post.txt", "w") as f: f.write(out)

    # Teardown
    h3.cmd("pkill -f 'http.server'")
    time.sleep(1)
    dump.send_signal(signal.SIGINT); dump.wait(timeout=3)
    net.stop()

    print("\nSaved artifacts:")
    print(f"  HTTP capture: {PCAP}")
    print( "  Client output: /tmp/http_post.txt")
    print( "  Server log:    /tmp/http_server.log")

if __name__ == "__main__":
    main()
