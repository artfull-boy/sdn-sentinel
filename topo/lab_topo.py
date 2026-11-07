#!/usr/bin/env python3
"""
Security of SDN - Lab 1: custom Mininet topology controlled by ONOS.

Topology (as given in the lab sheet):
  s1: hosts h1, h3  + data link to s2
  s2: hosts h2, h4  + data link to s1
  s3: hosts h5, h6  (no data link to s1/s2 in the sheet;
                     use --link-s3 to add an s2-s3 link)

All three switches open an OpenFlow 1.3 session to the ONOS controller
(out-of-band control channel over the Docker network).

Resulting switch ports (hosts are cabled first):
  s1: 1=h1, 2=h3, 3=s2
  s2: 1=h2, 2=h4, 3=s1, 4=s3 (only with --link-s3)
  s3: 1=h5, 2=h6, 3=s2 (only with --link-s3)

Usage:
  sudo python3 lab1_topo.py                        # exactly as specified
  sudo python3 lab1_topo.py --link-s3              # add the s2-s3 link
  sudo python3 lab1_topo.py --controller-ip 127.0.0.1
"""

import argparse
from functools import partial

from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

# (host name, IP address, switch it is attached to)
HOSTS = [
    ("h1", "10.0.1.1", "s1"),
    ("h3", "10.0.2.1", "s1"),
    ("h2", "10.0.1.2", "s2"),
    ("h4", "10.0.2.2", "s2"),
    ("h5", "10.0.3.1", "s3"),
    ("h6", "10.0.3.2", "s3"),
]

# A /16 mask puts every lab address (10.0.x.y) in the same IP network,
# so hosts reach each other directly (via ARP) without needing a router.
PREFIX_LEN = 16


class Lab1Topo(Topo):
    """Six hosts, three OpenFlow switches, optional s2-s3 link."""

    def build(self, link_s3=False):
        switches = {}
        for i in (1, 2, 3):
            name = "s%d" % i
            # 16 hex digits = 64-bit datapath ID -> shows as of:000000000000000i in ONOS
            switches[name] = self.addSwitch(name, dpid="%016x" % i)

        for name, ip, sw in HOSTS:
            num = int(name[1:])
            host = self.addHost(
                name,
                ip="%s/%d" % (ip, PREFIX_LEN),
                mac="00:00:00:00:00:%02x" % num,  # h1 -> 00:00:00:00:00:01
            )
            self.addLink(host, switches[sw])

        # Switch-to-switch (data plane) links
        self.addLink(switches["s1"], switches["s2"])
        if link_s3:
            self.addLink(switches["s2"], switches["s3"])


def main():
    parser = argparse.ArgumentParser(description="Lab 1 SDN topology for ONOS")
    parser.add_argument("--controller-ip", default="127.0.0.1",
                    help="ONOS IP (default: 127.0.0.1, port published by docker compose)")
    parser.add_argument("--controller-port", type=int, default=6653,
                        help="ONOS OpenFlow port (default: 6653)")
    parser.add_argument("--link-s3", action="store_true",
                        help="add a data-plane link between s2 and s3")
    args = parser.parse_args()

    setLogLevel("info")

    net = Mininet(
        topo=Lab1Topo(link_s3=args.link_s3),
        switch=partial(OVSSwitch, protocols="OpenFlow13", datapath="user"),
        controller=None,    # no local controller: we add ONOS below
        autoSetMacs=False,  # MACs are set explicitly in the topology
    )
    net.addController("c0", controller=RemoteController,
                      ip=args.controller_ip, port=args.controller_port)

    net.start()

    info("*** Waiting up to 30 s for switches to connect to ONOS\n")
    if not net.waitConnected(timeout=30):
        info("*** WARNING: not all switches connected. Is the ONOS container "
             "running with the openflow app active?\n")

    info("*** s2-s3 data link: %s\n"
         % ("ADDED" if args.link_s3 else "absent (as in the lab sheet)"))

    CLI(net)
    net.stop()


if __name__ == "__main__":
    main()
