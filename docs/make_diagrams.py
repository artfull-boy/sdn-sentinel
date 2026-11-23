#!/usr/bin/env python3
"""
Generate the Sentinel diagrams (SVG + PNG) in one consistent designed style.

    python3 docs/make_diagrams.py

Produces, in docs/:
    sentinel_architecture.png / .svg   the detection-and-response loop
    topology.png / .svg                the Mininet test network

Needs cairosvg (pip install cairosvg). Edit the builders below and re-run to
change a figure; commit the PNGs (the README embeds them) and the SVGs.
"""
import os
import cairosvg

HERE = os.path.dirname(os.path.abspath(__file__))

# ---- palette (matches the project's figure style) ------------------------
NAVY   = "#16213E"   # headings and node titles
SUB    = "#5B6472"   # sub-text
BLUE   = "#2B5BE2"   # accent: loop arrows, badges, our-service borders
BLUEF  = "#EAF0FD"   # our-service fill
WHITE  = "#FFFFFF"
GBORD  = "#C9D0DA"   # infra box border
DASH   = "#98A1AE"   # off-loop arrows / borders
RED    = "#D84343"   # attacker
GREEN  = "#2E9E6B"   # target
FONT   = "Helvetica, Arial, sans-serif"


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class SVG:
    def __init__(self, w, h):
        self.w, self.h = w, h
        self.parts = []

    def rect(self, x, y, w, h, fill, stroke, sw=2, rx=14, dash=None):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        self.parts.append(
            f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{d}/>')

    def text(self, x, y, s, size=22, color=NAVY, weight="normal", anchor="middle"):
        self.parts.append(
            f'<text x="{x}" y="{y}" font-family="{FONT}" font-size="{size}" '
            f'font-weight="{weight}" fill="{color}" text-anchor="{anchor}">{esc(s)}</text>')

    def node(self, x, y, w, h, title, lines, fill, stroke, dash=None):
        """A box with a bold title and grey sub-lines, vertically centred."""
        self.rect(x, y, w, h, fill, stroke, dash=dash)
        cx = x + w / 2
        n = len(lines)
        self.text(cx, y + h / 2 - 8 * n + 2, title, 23, NAVY, "bold")
        ty = y + h / 2 + 18
        for ln in lines:
            self.text(cx, ty, ln, 16.5, SUB)
            ty += 22

    def line(self, x1, y1, x2, y2, color, sw=3, dash=None, arrow=True):
        d = f' stroke-dasharray="{dash}"' if dash else ""
        m = ' marker-end="url(#ar)"' if (arrow and color == BLUE) else (
            ' marker-end="url(#arg)"' if arrow else "")
        self.parts.append(
            f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" '
            f'stroke-width="{sw}"{d}{m}/>')

    def path(self, d, color, sw=3, dash=None, arrow=True):
        da = f' stroke-dasharray="{dash}"' if dash else ""
        m = ' marker-end="url(#ar)"' if (arrow and color == BLUE) else ""
        self.parts.append(
            f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{sw}"{da}{m}/>')

    def badge(self, x, y, n):
        self.parts.append(f'<circle cx="{x}" cy="{y}" r="17" fill="{BLUE}"/>')
        self.text(x, y + 6, str(n), 19, WHITE, "bold")

    def dot(self, x, y, r, fill, stroke=None):
        s = f' stroke="{stroke}" stroke-width="2.5"' if stroke else ""
        self.parts.append(f'<circle cx="{x}" cy="{y}" r="{r}" fill="{fill}"{s}/>')

    def save(self, name):
        svg = (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" '
            f'height="{self.h}" viewBox="0 0 {self.w} {self.h}">'
            '<defs>'
            f'<marker id="ar" markerWidth="12" markerHeight="12" refX="9" refY="5" '
            f'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="{BLUE}"/></marker>'
            f'<marker id="arg" markerWidth="12" markerHeight="12" refX="9" refY="5" '
            f'orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="{DASH}"/></marker>'
            '</defs>'
            f'<rect width="{self.w}" height="{self.h}" fill="{WHITE}"/>'
            + "".join(self.parts) + "</svg>")
        with open(os.path.join(HERE, name + ".svg"), "w") as f:
            f.write(svg)
        cairosvg.svg2png(bytestring=svg.encode(), write_to=os.path.join(HERE, name + ".png"),
                         output_width=self.w * 2)
        print("wrote", name + ".png", "and", name + ".svg")


# ==========================================================================
# 1. Architecture: the detection-and-response loop
# ==========================================================================
def architecture():
    s = SVG(1780, 860)
    s.text(60, 72, "Sentinel: a self-defending SDN", 40, NAVY, "bold", "start")
    s.text(60, 110, "Learned detection and automatic mitigation on our Lab 1/2 "
           "environment (Mininet 2.3, Open vSwitch + OpenFlow 1.3, ONOS 2.7 in Docker)",
           20, SUB, "normal", "start")

    y = 300          # row-1 boxes
    bh = 150
    A = (60, y, 250, bh)      # Mininet + OVS
    B = (420, y, 250, bh)     # ONOS
    C = (780, y, 330, bh)     # ML detector
    D = (1240, y, 250, bh)    # Mitigation
    s.node(*A, "Mininet + OVS", ["3 switches, 6 hosts", "attacks run here"], WHITE, GBORD)
    s.node(*B, "ONOS controller", ["reactive forwarding (fwd)", "REST API, Docker"], WHITE, GBORD)
    s.node(*C, "ML detector", ["polls ONOS every 2 s, 12 features/port",
           "1. Isolation Forest", "2. Random Forest (type)"], BLUEF, BLUE)
    s.node(*D, "Mitigation engine", ["meter or drop rule", "rollback, guardrails"], BLUEF, BLUE)

    midy = y + bh / 2
    # forward arrows + badges
    s.line(310, midy, 420, midy, BLUE); s.badge(365, midy, 1); s.text(365, midy - 26, "OpenFlow", 16, SUB)
    s.line(670, midy, 780, midy, BLUE); s.badge(725, midy, 2); s.text(725, midy - 26, "REST, 2 s", 16, SUB)
    s.line(1110, midy, 1240, midy, BLUE); s.badge(1175, midy, 3); s.text(1175, midy - 34, "alert +", 16, SUB); s.text(1175, midy - 16, "attack type", 16, SUB)
    # loop back: Mitigation -> ONOS over the top
    s.path(f"M1365,{y} L1365,180 L545,180 L545,{y}", BLUE)
    s.badge(955, 180, 4)
    s.text(955, 158, "countermeasure installed through ONOS REST (meter or drop rule), removed after recovery",
           17, BLUE, "bold")

    # row-2: monitoring (off-loop, dashed)
    y2 = 620
    PROM = (700, y2, 240, 110)
    GRAF = (360, y2, 240, 110)
    BRID = (420, y2, 0, 0)  # not drawn as a box; shown as label under ONOS feed
    s.node(*PROM, "Prometheus", ["stores the metrics"], WHITE, GBORD)
    s.node(*GRAF, "Grafana", ["live security dashboard"], WHITE, GBORD)
    # metrics dashed down from detector and engine to Prometheus
    s.line(900, y + bh, 860, y2, DASH, 2.5, "7 6"); s.text(905, (y + bh + y2) / 2, "metrics", 15, SUB, "normal", "start")
    s.line(1300, y + bh, 940, y2 + 20, DASH, 2.5, "7 6")
    s.text(1140, 575, "metrics", 15, SUB)
    s.line(700, y2 + 55, 600, y2 + 55, DASH, 2.5, "7 6")  # Prometheus -> Grafana

    # Colab (offline, dashed) -> model file -> detector
    COL = (1480, y2, 230, 110)
    s.node(*COL, "Google Colab", ["offline training"], WHITE, DASH, dash="7 6")
    s.path(f"M1595,{y2} L1595,470 L945,470 L945,{y + bh}", DASH, 2.5, "7 6")
    s.text(1300, 455, "trained model file", 16, SUB)

    # legend
    ly = 820
    s.rect(60, ly - 14, 26, 20, BLUEF, BLUE, 2, 5)
    s.text(96, ly + 3, "Python services we write", 17, NAVY, "normal", "start")
    s.line(420, ly - 4, 470, ly - 4, BLUE, 3, arrow=False)
    s.text(480, ly + 3, "detection and response loop, 1 to 4", 17, NAVY, "normal", "start")
    s.line(900, ly - 4, 950, ly - 4, DASH, 2.5, "7 6", arrow=False)
    s.text(960, ly + 3, "monitoring or offline only (not in the decision path)", 17, NAVY, "normal", "start")
    s.save("sentinel_architecture")


# ==========================================================================
# 2. Topology: the Mininet test network
# ==========================================================================
def topology():
    s = SVG(1320, 760)
    s.text(60, 66, "Test network", 34, NAVY, "bold", "start")
    s.text(60, 100, "6 hosts, 3 switches, one /16 subnet. h1 is the attacker, h6 the target.",
           19, SUB, "normal", "start")

    # ONOS controller at the top
    s.rect(540, 150, 240, 74, BLUEF, BLUE, 2)
    s.text(660, 184, "ONOS controller", 22, NAVY, "bold")
    s.text(660, 208, "OpenFlow 1.3 : 6653", 15, SUB)

    sw_y = 420
    sw = {"s1": 300, "s2": 660, "s3": 1020}
    # control links (dashed) from ONOS to each switch
    for x in sw.values():
        s.line(660, 224, x, sw_y - 42, DASH, 2, "6 6", arrow=False)
    # data links between switches
    s.line(342, sw_y, 618, sw_y, NAVY, 3, arrow=False)
    s.text(480, sw_y - 12, "s1:3 - s2:3", 15, SUB)
    s.line(702, sw_y, 978, sw_y, NAVY, 3, arrow=False)
    s.text(840, sw_y - 12, "s2:4 - s3:3", 15, SUB)
    # switches
    for name, x in sw.items():
        s.rect(x - 52, sw_y - 42, 104, 84, WHITE, GBORD, 2, 12)
        s.text(x, sw_y - 4, name, 24, NAVY, "bold")
        s.text(x, sw_y + 22, "OVS", 14, SUB)

    # hosts: (name, ip, switch, port, side, colour)
    hosts = [
        ("h1", "10.0.1.1", "s1", "1", "l", RED),
        ("h3", "10.0.2.1", "s1", "2", "r", NAVY),
        ("h2", "10.0.1.2", "s2", "1", "l", NAVY),
        ("h4", "10.0.2.2", "s2", "2", "r", NAVY),
        ("h5", "10.0.3.1", "s3", "1", "l", NAVY),
        ("h6", "10.0.3.2", "s3", "2", "r", GREEN),
    ]
    hy = 620
    for name, ip, swn, port, side, col in hosts:
        sx = sw[swn]
        hx = sx - 95 if side == "l" else sx + 95
        s.line(sx + (-30 if side == "l" else 30), sw_y + 42, hx, hy - 40, NAVY, 2, arrow=False)
        s.text((sx + hx) / 2 + (-18 if side == "l" else 18), (sw_y + 42 + hy - 40) / 2,
               swn + ":" + port, 13, SUB)
        fill = BLUEF if col == NAVY else ("#FBE9E9" if col == RED else "#E7F5EE")
        s.rect(hx - 70, hy - 40, 140, 80, fill, col, 2, 12)
        s.text(hx, hy - 8, name, 22, NAVY, "bold")
        s.text(hx, hy + 16, ip, 15, SUB)
        tag = "attacker" if col == RED else ("target" if col == GREEN else "")
        if tag:
            s.text(hx, hy + 60, tag, 15, col, "bold")
    s.save("topology")


if __name__ == "__main__":
    architecture()
    topology()
