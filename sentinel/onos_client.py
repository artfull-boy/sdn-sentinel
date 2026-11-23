"""Thin ONOS REST client: meters, flows, links, hosts. Stdlib only."""
import base64
import json
import os
import urllib.request

ONOS = os.environ.get("ONOS_URL", "http://127.0.0.1:8181/onos/v1")
AUTH = "Basic " + base64.b64encode(os.environ.get("ONOS_AUTH", "onos:rocks").encode()).decode()
# How long to wait for ONOS. Under a heavy flood a single REST call can take several seconds;
# giving up too early leaves the attacking port unprotected.
TIMEOUT = float(os.environ.get("ONOS_TIMEOUT", 10))
APP = "org.onosproject.rest"


def _req(method, path, body=None):
    headers = {"Authorization": AUTH, "Accept": "application/json"}
    data = None
    if body is not None:  # ONOS answers 415 to a Content-Type on a request without a body
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    r = urllib.request.Request(ONOS + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(r, timeout=TIMEOUT) as resp:
        raw = resp.read()
        return resp.headers.get("Location"), (json.loads(raw) if raw else None)


def _new_id(location):
    # ONOS answers 201 with Location: .../flows/of:0000000000000001/<id> (same for meters)
    return location.rstrip("/").rsplit("/", 1)[-1]


def add_meter(dev, pps):
    loc, _ = _req("POST", f"/meters/{dev}", {
        "deviceId": dev, "unit": "PKTS_PER_SEC", "burst": False,
        "bands": [{"type": "DROP", "rate": pps, "burstSize": pps}]})
    return _new_id(loc)


def add_flow(dev, priority, criteria, instructions):
    loc, _ = _req("POST", f"/flows/{dev}?appId={APP}", {
        "priority": priority, "isPermanent": True, "timeout": 0, "deviceId": dev,
        "selector": {"criteria": criteria}, "treatment": {"instructions": instructions}})
    return _new_id(loc)


# Priorities sit above ONOS fwd (10) and the ARP/LLDP intercepts (40000).
def meter_port(dev, port, meter_id):
    return add_flow(dev, 49000, [{"type": "IN_PORT", "port": int(port)}],
                    [{"type": "METER", "meterId": str(meter_id)}, {"type": "OUTPUT", "port": "CONTROLLER"}])


def drop_port(dev, port):
    return add_flow(dev, 50000, [{"type": "IN_PORT", "port": int(port)}], [])  # empty = actions=drop


def drop_mac(dev, port, mac):
    return add_flow(dev, 51000, [{"type": "IN_PORT", "port": int(port)}, {"type": "ETH_SRC", "mac": mac}], [])


def delete_flow(dev, flow_id):
    _req("DELETE", f"/flows/{dev}/{flow_id}")


def delete_meter(dev, meter_id):
    _req("DELETE", f"/meters/{dev}/{meter_id}")


def purge_mac_flows(mac):
    """Delete the fwd app's learnt flows for a MAC so they are re-learnt from its real port.
    Needed after spoofing: they still point at the impostor and live traffic keeps them alive."""
    _, data = _req("GET", "/flows")
    stale = [f for f in data["flows"] if f.get("appId") == "org.onosproject.fwd" and
             any(c.get("mac", "").lower() == mac.lower() for c in f["selector"]["criteria"])]
    for f in stale:
        delete_flow(f["deviceId"], f["id"])
    return len(stale)


def flow_packets(dev, flow_id):
    """(packets, refreshed_at) for one flow rule: packets that matched it since it was installed,
    and when ONOS last read that count from the switch (s). ONOS refreshes it about every 5 s."""
    _, data = _req("GET", f"/flows/{dev}/{flow_id}")
    f = data["flows"][0]
    return int(f.get("packets", 0)), f.get("lastSeen", 0) / 1000.0


def infra_ports():
    """Every (device, port) that touches another switch. Never mitigate these."""
    _, data = _req("GET", "/links")
    return {(end["device"], str(end["port"])) for link in data["links"] for end in (link["src"], link["dst"])}


def hosts():
    """[(mac, (device, port))] as ONOS currently sees them."""
    _, data = _req("GET", "/hosts")
    return [(h["mac"], (loc["elementId"], str(loc["port"])))
            for h in data["hosts"] for loc in (h.get("locations") or [h["location"]])]
