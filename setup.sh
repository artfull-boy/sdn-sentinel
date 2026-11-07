#!/usr/bin/env bash
set -e
sudo apt update
sudo apt install -y mininet openvswitch-switch docker.io docker-compose git python3-venv
sudo usermod -aG docker "$USER"
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
