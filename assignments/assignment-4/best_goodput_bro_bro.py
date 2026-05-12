import argparse
import ipaddress
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict, deque

import yaml
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch


# Builds the topology from the YAML: routers, hosts, switches and links.
# A switch sN is added automatically when two or more hosts share the same subnet.
class Network:
    def __init__(self, data):
        self.routers = {}
        self.hosts = {}
        self.switches = []
        self.links = []
        self.adj = defaultdict(list)
        self.gateway = {}  # host -> (gateway_router, gateway_iface)

        # Parse routers
        for r, ifaces in data.get("routers", {}).items():
            self.routers[r] = {}
            for name, c in ifaces.items():
                self.routers[r][name] = (c["address"], c["mask"], c.get("cost"))

        # Parse hosts
        for h, ifaces in data.get("hosts", {}).items():
            ((name, c),) = ifaces.items()
            self.hosts[h] = (c["address"], c["mask"])

        # Group every interface by its IPv4 subnet -> each group is a link
        by_subnet = defaultdict(list)
        for r, ifs in self.routers.items():
            for name, (addr, mask, cost) in ifs.items():
                # Calculate the base network address (subnet) from the IP and subnet mask
                net = ipaddress.ip_interface(f"{addr}/{mask}").network
                # Append router interface details.
                # Tuple format: (device_type, device_id, interface_name, interface_cost)
                by_subnet[net].append(("router", r, name, cost))

        for h, (addr, mask) in self.hosts.items():
            # Calculate the base network address (subnet) for the host
            net = ipaddress.ip_interface(f"{addr}/{mask}").network
            # Append host interface details.
            # Hosts are assumed to use 'eth0' by default and do not use routing costs (None).
            by_subnet[net].append(("host", h, "eth0", None))

        sw_count = 0
        # Iterate through each subnet to build the actual links
        for group in by_subnet.values():
            rs = [x for x in group if x[0] == "router"]
            hs = [x for x in group if x[0] == "host"]

            # router-router point-to-point link
            if not hs:
                # Unpack the two router tuples.
                (_, ra, ia, ca), (_, rb, ib, cb) = rs
                cap = ca if ca is not None else (cb if cb is not None else 1)
                self.add_link(ra, rb, cap, ia, ib)

            # subnet contains exactly one router and one or more hosts
            else:
                _, rname, riface, _ = rs[0]
                for _, h, _, _ in hs:
                    self.gateway[h] = (rname, riface)

                if len(hs) == 1:
                    _, h, hi, _ = hs[0]
                    self.add_link(h, rname, None, hi, riface)

                else:
                    sw_count += 1
                    sw = f"s{sw_count}"
                    self.switches.append(sw)
                    self.add_link(sw, rname, None, None, riface)
                    for _, h, hi, _ in hs:
                        self.add_link(h, sw, None, hi, None)

    def add_link(self, a, b, cap, ia, ib):
        idx = len(self.links)
        self.links.append((a, b, cap, ia, ib))
        self.adj[a].append((b, idx))
        self.adj[b].append((a, idx))

    def nodes(self):
        return list(self.routers) + list(self.hosts) + self.switches

    def router_ip(self, r, iface):
        return self.routers[r][iface][0]

    def host_ip(self, h):
        return self.hosts[h][0]


# Builds the max-min fairness multi-commodity flow LP in CPLEX LP
# format and solves it through glpsol.
class Optimizer:
    def __init__(self, net, demands):
        self.net = net
        self.demands = demands
        self.alpha = None
        self.flows = {}
        self.goodputs = {}

    def directed_edges(self):
        edges = []
        for a, b, cap, _, _ in self.net.links:
            edges.append((a, b, cap))
            edges.append((b, a, cap))
        return edges

    def build_lp(self):
        EPS = 1e-4
        obj = ["alpha"] + [f"{EPS / d['rate']:.6f} g_{d['idx']}" for d in self.demands]
        lines = ["Maximize", " obj: " + " + ".join(obj), "Subject To"]
        c = 1
        lines.append(f" c{c}: alpha <= 1")

        for u, v, cap in self.directed_edges():
            if cap is None:
                continue
            terms = " + ".join(f"f_{d['idx']}_{u}_{v}" for d in self.demands)
            c += 1
            lines.append(f" c{c}: {terms} <= {cap}")

        for d in self.demands:
            i = d["idx"]
            # g_i >= r_i * alpha  e  g_i <= r_i
            c += 1
            lines.append(f" c{c}: g_{i} - {d['rate']} alpha >= 0")
            c += 1
            lines.append(f" c{c}: g_{i} <= {d['rate']}")

            for node in self.net.nodes():
                nbrs = self.net.adj[node]
                if not nbrs:
                    continue
                out_t = [f"f_{i}_{node}_{n}" for n, _ in nbrs]
                in_t = [f"f_{i}_{n}_{node}" for n, _ in nbrs]
                expr = " + ".join(out_t) + " - " + " - ".join(in_t)
                c += 1
                if node == d["src"]:
                    lines.append(f" c{c}: {expr} - g_{i} = 0")
                elif node == d["dst"]:
                    lines.append(f" c{c}: {expr} + g_{i} = 0")
                else:
                    lines.append(f" c{c}: {expr} = 0")

        lines.append("Bounds")
        lines.append(" 0 <= alpha <= 1")
        for d in self.demands:
            lines.append(f" 0 <= g_{d['idx']} <= {d['rate']}")
            for u, v, _ in self.directed_edges():
                lines.append(f" f_{d['idx']}_{u}_{v} >= 0")
        lines.append("End")
        return "\n".join(lines) + "\n"

    def solve(self):
        lp_text = self.build_lp()
        # Write the LP to a temporary file and call glpsol to solve it, capturing the output.
        with tempfile.TemporaryDirectory() as tmp:
            lp_file = os.path.join(tmp, "p.lp")  # problem file for glpsol
            sol_file = os.path.join(tmp, "sol.txt")  # solution output from glpsol
            with open(lp_file, "w") as f:
                f.write(lp_text)

            r = subprocess.run(
                ["glpsol", "--lp", lp_file, "-o", sol_file],
                capture_output=True,
                text=True,
            )
            if r.returncode != 0:
                raise RuntimeError(f"glpsol failed:\n{r.stderr}")

            with open(sol_file) as f:
                self.parse_solution(f.read())

    def parse_solution(self, text):
        # Flag to track if we are currently parsing the variable values section of the glpsol output
        in_cols = False
        for line in text.splitlines():
            # Look for the line that indicates the start of the variable values section, which contains the flow values and alpha.
            if "Column name" in line and "Activity" in line:
                in_cols = True
                continue

            if not in_cols:
                continue

            # An empty line indicates the end of the variable values section.
            if not line.strip():
                break

            # Each line in the variable values section typically has the format:
            # <index> <variable_name> <activity_value> ...
            m = re.match(r"\s*\d+\s+(\S+)\s+\S+\s+([-+\d.eE]+)", line)
            if not m:
                continue
            # Extract the variable name and its corresponding value.
            name, val = m.group(1), float(m.group(2))
            if name == "alpha":
                self.alpha = val
            elif name.startswith("g_"):
                idx = int(name.split("_")[1])
                self.goodputs[idx] = val
            else:
                self.flows[name] = val
        if self.alpha is None:
            raise RuntimeError("Could not parse alpha from glpsol output.")


# Builds the Mininet emulation and installs MPLS rules implementing the routing scheme found by the optimizer.
class Emulator:
    def __init__(self, net, demands, alpha, flows):
        self.net = net
        self.demands = demands
        self.alpha = alpha
        self.flows = flows
        # (u, v) -> (iface_on_u, iface_on_v) for quick lookup
        self.ifaces = {}
        for a, b, _, ia, ib in net.links:
            self.ifaces[(a, b)] = (ia, ib)
            self.ifaces[(b, a)] = (ib, ia)

    def run(self):
        setLogLevel("info")
        mn = Mininet(switch=OVSSwitch, link=TCLink, controller=None, autoSetMacs=True)

        nodes = {}
        for r in self.net.routers:
            nodes[r] = mn.addHost(r, ip=None)
        for h in self.net.hosts:
            nodes[h] = mn.addHost(h, ip=None)
        for s in self.net.switches:
            nodes[s] = mn.addSwitch(s, failMode="standalone")

        # Add links and assign IP addresses to each interface. Also build a
        # (node, yaml_iface) -> mininet_device_name lookup, because YAML
        # names ("eth0") don't exist as devices in the node namespace
        # (Mininet creates them as "r1-eth0", etc.).
        self.dev_of = {}
        for a, b, cap, ia, ib in self.net.links:
            bw = cap if cap is not None else 1000
            link = mn.addLink(nodes[a], nodes[b], bw=float(bw))
            self.set_ip(link.intf1, a, ia)
            self.set_ip(link.intf2, b, ib)
            if ia is not None:
                self.dev_of[(a, ia)] = link.intf1.name
            if ib is not None:
                self.dev_of[(b, ib)] = link.intf2.name

        mn.build()
        mn.start()

        # Enable IP forwarding + MPLS on every router
        for r in self.net.routers:
            n = nodes[r]
            n.cmd("sysctl -w net.ipv4.ip_forward=1")
            n.cmd("modprobe mpls_router")
            n.cmd("modprobe mpls_iptunnel")
            n.cmd("sysctl -w net.mpls.platform_labels=1048575")
            for intf in n.intfList():
                if intf.name != "lo":
                    n.cmd(f"sysctl -w net.mpls.conf.{intf.name}.input=1")

        # Default gateway on every host
        for h in self.net.hosts:
            gw_r, gw_i = self.net.gateway[h]
            nodes[h].cmd(f"ip route add default via {self.net.router_ip(gw_r, gw_i)}")

        # Full IPv4 reachability between routers. MPLS policy rules added
        # below take precedence for the demand flows.
        self.install_static_routes(nodes)

        # Install MPLS rules following the optimal flow paths
        label = 100
        for d in self.demands:
            paths = self.decompose(d)
            if not paths:
                continue

            # Keep only the router part of each path
            labelled = []
            for path, rate in paths:
                rp = [n for n in path if n in self.net.routers]
                if rp:
                    labelled.append((label, rp, rate))
                    label += 1
            if not labelled:
                continue

            self.program_source(nodes, d, labelled)
            self.program_transit(nodes, d, labelled)

        CLI(mn)
        mn.stop()

    def set_ip(self, intf, node, iface_name):
        if iface_name is None:
            return  # switch endpoint
        if node in self.net.routers:
            addr, mask, _ = self.net.routers[node][iface_name]
        else:
            addr, mask = self.net.hosts[node]
        plen = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
        intf.setIP(f"{addr}/{plen}")

    def install_static_routes(self, nodes):
        # Enumerate every subnet and the routers that own an interface on it.
        subnet_owners = {}
        for r, ifs in self.net.routers.items():
            for addr, mask, _ in ifs.values():
                net = ipaddress.ip_interface(f"{addr}/{mask}").network
                subnet_owners.setdefault(net, set()).add(r)
        for h, (addr, mask) in self.net.hosts.items():
            net = ipaddress.ip_interface(f"{addr}/{mask}").network
            gw_r, _ = self.net.gateway[h]
            subnet_owners.setdefault(net, set()).add(gw_r)

        # For each router add a route to every subnet it does not own.
        for r in self.net.routers:
            own = {
                ipaddress.ip_interface(f"{a}/{m}").network
                for (a, m, _) in self.net.routers[r].values()
            }
            for subnet, owners in subnet_owners.items():
                if subnet in own:
                    continue
                nxt = self.next_hop_router(r, owners)
                if nxt is None:
                    continue
                iface_r, iface_nxt = self.ifaces[(r, nxt)]
                nh_ip = self.net.router_ip(nxt, iface_nxt)
                dev = self.dev_of[(r, iface_r)]
                nodes[r].cmd(f"ip route add {subnet} via {nh_ip} dev {dev}")

    def next_hop_router(self, src, targets):
        # BFS over routers only: return the first router after src on a
        # shortest path to any router in targets.
        if src in targets:
            return None
        prev = {src: None}
        q = deque([src])
        found = None
        while q:
            u = q.popleft()
            if u != src and u in targets:
                found = u
                break
            for v, _ in self.net.adj[u]:
                if v in prev or v not in self.net.routers:
                    continue
                prev[v] = u
                q.append(v)
        if found is None:
            return None
        cur = found
        while prev[cur] != src:
            cur = prev[cur]
        return cur

    def program_source(self, nodes, d, labelled):
        # On the source gateway: per-demand routing table that encapsulates
        # packets with the appropriate MPLS label(s). Policy routing via
        # `ip rule from <src> to <dst>` keeps demands sharing the same
        # gateway separated.
        gw, _ = self.net.gateway[d["src"]]
        src_ip = self.net.host_ip(d["src"])
        dst_ip = self.net.host_ip(d["dst"])
        table = 100 + d["idx"]

        nexthops = []
        for lbl, rp, rate in labelled:
            if len(rp) < 2:
                continue  # src and dst share the gateway: plain IP handles it
            nxt = rp[1]
            iface_gw, iface_nxt = self.ifaces[(gw, nxt)]
            nh_ip = self.net.router_ip(nxt, iface_nxt)
            dev = self.dev_of[(gw, iface_gw)]
            nexthops.append((lbl, nh_ip, max(1, int(round(rate))), dev))

        if not nexthops:
            return

        nodes[gw].cmd(f"ip rule add from {src_ip}/32 to {dst_ip}/32 lookup {table}")

        if len(nexthops) == 1:
            lbl, nh, _, dev = nexthops[0]
            nodes[gw].cmd(
                f"ip route add table {table} {dst_ip}/32 "
                f"encap mpls {lbl} via {nh} dev {dev}"
            )
        else:
            clauses = " ".join(
                f"nexthop encap mpls {l} via {ip} dev {dev} weight {w}"
                for l, ip, w, dev in nexthops
            )
            nodes[gw].cmd(f"ip route add table {table} {dst_ip}/32 {clauses}")

    def program_transit(self, nodes, d, labelled):
        # Transit routers swap the label to itself (preserve it); the
        # destination gateway pops the label and forwards via IPv4.
        gw, _ = self.net.gateway[d["src"]]
        dst_ip = self.net.host_ip(d["dst"])
        for lbl, rp, _ in labelled:
            for k, cur in enumerate(rp):
                if k == 0 and cur == gw:
                    continue  # source gateway already programmed
                if k + 1 < len(rp):
                    nxt = rp[k + 1]
                    iface_cur, iface_nxt = self.ifaces[(cur, nxt)]
                    nh_ip = self.net.router_ip(nxt, iface_nxt)
                    dev = self.dev_of[(cur, iface_cur)]
                    nodes[cur].cmd(
                        f"ip -f mpls route add {lbl} as {lbl} "
                        f"via inet {nh_ip} dev {dev}"
                    )
                else:
                    nodes[cur].cmd(f"ip -f mpls route add {lbl} via inet {dst_ip}")

    # Decompose the LP flow of demand d into source-to-destination paths via BFS on the residual graph.
    def decompose(self, d):
        EPS = 1e-9
        res = {}
        for node, nbrs in self.net.adj.items():
            for nbr, _ in nbrs:
                res[(node, nbr)] = self.flows.get(f"f_{d['idx']}_{node}_{nbr}", 0.0)

        paths = []
        while True:
            path = self.bfs(d["src"], d["dst"], res, EPS)
            if not path:
                break
            bn = min(res[(path[i], path[i + 1])] for i in range(len(path) - 1))
            if bn <= EPS:
                break
            for i in range(len(path) - 1):
                res[(path[i], path[i + 1])] -= bn
            paths.append((path, bn))
        return paths

    def bfs(self, src, dst, res, eps):
        prev = {src: None}
        q = deque([src])
        while q:
            u = q.popleft()
            if u == dst:
                path = [u]
                while prev[path[-1]] is not None:
                    path.append(prev[path[-1]])
                return list(reversed(path))
            for v, _ in self.net.adj[u]:
                if v not in prev and res.get((u, v), 0.0) > eps:
                    prev[v] = u
                    q.append(v)
        return None


def main():
    parser = argparse.ArgumentParser(
        description="A tool to define the emulation of a network configured "
        "to achieve the best overall goodput under a given set "
        "of flow demands."
    )
    parser.add_argument(
        "definition", help="the definition file of the network and flow demands in YAML"
    )
    parser.add_argument(
        "-p",
        "--print",
        action="store_true",
        help="print the optimal goodput for each flow and exit",
    )
    parser.add_argument(
        "-l",
        "--lp",
        action="store_true",
        help="print the definition of the optimization problem in CPLEX LP format",
    )
    args = parser.parse_args()

    with open(args.definition) as f:
        data = yaml.safe_load(f)

    net = Network(data)
    # Parse the flow demands, assigning an index to each for variable naming in the LP.
    demands = [
        {"idx": i + 1, "src": d["src"], "dst": d["dst"], "rate": float(d["rate"])}
        for i, d in enumerate(data.get("demands", []))
    ]

    opt = Optimizer(net, demands)

    if args.lp:
        sys.stdout.write(opt.build_lp())
        return

    opt.solve()

    if args.print:
        for d in demands:
            goodput = round(opt.goodputs[d["idx"]], 6)
            print(f"The best goodput for flow demand #{d['idx']} is {goodput:g} Mbps")
        return

    Emulator(net, demands, opt.alpha, opt.flows).run()


if __name__ == "__main__":
    main()
