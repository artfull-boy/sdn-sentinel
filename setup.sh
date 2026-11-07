#!/usr/bin/env bash
# One-time setup for a teammate's Kali VM.
set -e

# System packages (not pip): Mininet, Open vSwitch, iperf (traffic_gen),
# Docker (ONOS container), git, and pip itself.
sudo apt update
sudo apt install -y mininet openvswitch-switch iperf \
                    docker.io docker-compose-plugin git python3-pip

# Let this user run docker without sudo (applies after next login).
sudo usermod -aG docker "$USER"

# Python deps go into the SYSTEM python, not a venv: the attack scripts run as
# root through `sudo` + `mnexec`, which ignores a venv and uses /usr/bin/python3.
# --break-system-packages is required on recent Kali/Debian; fine on a lab VM.
#sudo pip install -r requirements.txt --break-system-packages

echo
echo "Setup done."
echo "Log out and back in once so the 'docker' group takes effect, then:"
echo "  docker compose up -d"
echo "  sudo python3 topo/lab_topo.py --link-s3"
