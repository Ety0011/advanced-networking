import argparse
import ipaddress
import os
import subprocess
import tempfile

import yaml
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Node, OVSSwitch

# I discussed with Gianluca Viviano and Giovanni Elisei the choice of
# using a whole multi-commodity flow LP instead of a fractional one.


def parse_command_line():
    parser = argparse.ArgumentParser(
        description=(
            "A tool to define the emulation of a network configured to achieve "
            "the best overall goodput under a given set of flow demands."
        )
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
    parser.add_argument(
        "definition", help="the definition file of the network and flow demands in YAML"
    )
    return parser.parse_args()


def get_subnets(topology):
    subnets = {}

    for category in ("routers", "hosts"):
        for name, interfaces in topology[category].items():
            for interface, config in interfaces.items():
                address = config["address"]
                mask = config["mask"]
                subnet_address = ipaddress.IPv4Network(
                    f"{address}/{mask}", strict=False
                )
                if subnet_address not in subnets:
                    subnets[subnet_address] = {
                        "routers": [],
                        "hosts": [],
                        "switch": None,
                        "cost": 1,
                    }
                cost = config.get("cost", 1)
                if cost > subnets[subnet_address]["cost"]:
                    subnets[subnet_address]["cost"] = cost
                node = {
                    "name": name,
                    "interface": interface,
                    "address": address,
                }
                subnets[subnet_address][category].append(node)

    switch_id = 1
    for subnet in subnets.values():
        if len(subnet["hosts"]) >= 2 or len(subnet["routers"]) >= 3:
            subnet["switch"] = f"s{switch_id}"
            switch_id += 1

    return subnets


def print_graphviz(subnets):
    names = set()
    edges = set()

    for subnet in subnets.values():
        cost = subnet["cost"]
        routers = subnet["routers"]
        for i in range(len(routers)):
            names.add(routers[i]["name"])
            for j in range(i + 1, len(routers)):
                edge = (*sorted((routers[i]["name"], routers[j]["name"])), cost)
                edges.add(edge)

    print("graph Network {")
    for r_name in sorted(names):
        print(f"    {r_name} [shape=circle];")
    for edge in sorted(edges):
        print(f'    {edge[0]} -- {edge[1]} [label="{edge[2]}"];')
    print("}")


def get_graph(subnets):
    graph = {}

    for subnet in subnets.values():
        routers = subnet["routers"]
        for i in range(len(routers)):
            src = routers[i]
            if src["name"] not in graph:
                graph[src["name"]] = []
            for j in range(len(routers)):
                if i == j:
                    continue
                dst = routers[j]
                graph[src["name"]].append(
                    {
                        "interface": src["interface"],
                        "to": dst["name"],
                        "address": dst["address"],
                        "cost": subnet["cost"],
                    }
                )

    return graph


def host_to_router(host_name, topology, subnets):
    host_config = topology["hosts"][host_name]["eth0"]
    address = host_config["address"]
    mask = host_config["mask"]
    subnet_address = ipaddress.IPv4Network(f"{address}/{mask}", strict=False)
    return subnets[subnet_address]["routers"][0]["name"]


def get_demands(topology, subnets):
    return [
        {
            "src": host_to_router(demand["src"], topology, subnets),
            "dst": host_to_router(demand["dst"], topology, subnets),
            "rate": demand["rate"],
        }
        for demand in topology["demands"]
    ]


def build_lp(topology, subnets, graph):
    lines = ["Maximize"]
    demands = get_demands(topology, subnets)

    # small weight on g_i to fill remaining capacity once alpha is maximized
    obj_terms = ["alpha"] + [f"0.001 g{i}" for i in range(len(demands))]
    lines.append(" obj: " + " + ".join(obj_terms))

    lines.append("Subject to")
    router_names = sorted(graph.keys())

    unique_links = []
    seen = set()
    for u in router_names:
        for edge in graph[u]:
            v = edge["to"]
            pair = tuple(sorted((u, v)))
            if pair not in seen:
                unique_links.append(pair)
                seen.add(pair)

    for i, demand in enumerate(demands):
        # flow conservation for binary path indicator x: -1 at src, +1 at dst
        for r_name in router_names:
            terms = []
            for u in router_names:
                for edge in graph[u]:
                    v = edge["to"]
                    if u == r_name:
                        terms.append(f"- x{i}_{u}_{v}")
                    if v == r_name:
                        terms.append(f"+ x{i}_{u}_{v}")

            rhs = 0
            if r_name == demand["src"]:
                rhs = -1
            elif r_name == demand["dst"]:
                rhs = 1

            expr = " ".join(terms).strip()
            if expr.startswith("+ "):
                expr = expr[2:]
            if expr:
                lines.append(f" ind_bal_{i}_{r_name}: {expr} = {rhs}")

        # flow rate conservation for f; g_i is added at src and removed at dst
        for r_name in router_names:
            terms = []
            for u in router_names:
                for edge in graph[u]:
                    v = edge["to"]
                    if u == r_name:
                        terms.append(f"- f{i}_{u}_{v}")
                    if v == r_name:
                        terms.append(f"+ f{i}_{u}_{v}")

            if r_name == demand["src"]:
                terms.append(f"+ g{i}")
            elif r_name == demand["dst"]:
                terms.append(f"- g{i}")

            expr = " ".join(terms).strip()
            if expr.startswith("+ "):
                expr = expr[2:]
            if expr:
                lines.append(f" rate_bal_{i}_{r_name}: {expr} = 0")

        # single-path: at most one incoming and one outgoing edge per flow per node
        for r_name in router_names:
            in_vars = [
                f"x{i}_{u}_{r_name}"
                for u in router_names
                for e in graph[u]
                if e["to"] == r_name
            ]
            out_vars = [f"x{i}_{r_name}_{e['to']}" for e in graph[r_name]]
            if in_vars:
                lines.append(f" in_excl_{i}_{r_name}: " + " + ".join(in_vars) + " <= 1")
            if out_vars:
                lines.append(
                    f" out_excl_{i}_{r_name}: " + " + ".join(out_vars) + " <= 1"
                )

        # f can only be nonzero on edges selected by x
        for u in router_names:
            for edge in graph[u]:
                v = edge["to"]
                cost = edge["cost"]
                lines.append(
                    f" couple_{i}_{u}_{v}: f{i}_{u}_{v} - {cost} x{i}_{u}_{v} <= 0"
                )

        lines.append(f" g_cap_{i}: g{i} <= {demand['rate']}")
        # g_i >= alpha * r_i enforces alpha as the min effectiveness ratio
        lines.append(f" g_eff_{i}: g{i} - {demand['rate']} alpha >= 0")
        lines.append("")

    # both directions share the same physical link capacity
    for u, v in unique_links:
        cost = next(e["cost"] for e in graph[u] if e["to"] == v)
        link_rates = [
            f"f{i}_{a}_{b}" for i in range(len(demands)) for a, b in ((u, v), (v, u))
        ]
        lines.append(f" cap_{u}_{v}: " + " + ".join(link_rates) + f" <= {cost}")

    lines.append("Bounds")
    lines.append(" 0 <= alpha <= 1")
    lines.append("Binary")
    for i in range(len(demands)):
        for u in router_names:
            for edge in graph[u]:
                lines.append(f" x{i}_{u}_{edge['to']}")
    lines.append("End")
    return "\n".join(lines)


def parse_solution(report):
    values = {}
    in_columns = False
    past_header = False
    for line in report.splitlines():
        if "No. Column name" in line:
            in_columns = True
            continue
        if not in_columns:
            continue
        if line.strip().startswith("------"):
            past_header = True
            continue
        if not past_header:
            continue
        if not line.strip():
            break
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            # GLPK marks basic variables with '*'; value is then in column 4
            if parts[2] == "*":
                values[parts[1]] = float(parts[3])
            else:
                values[parts[1]] = float(parts[2])
        except ValueError:
            continue
    return values


def solve_lp(lp_text):
    with tempfile.TemporaryDirectory() as tmp:
        lp_path = os.path.join(tmp, "problem.lp")
        sol_path = os.path.join(tmp, "problem.sol")

        with open(lp_path, "w") as f:
            f.write(lp_text)

        result = subprocess.run(
            ["glpsol", "--lp", lp_path, "-o", sol_path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"glpsol failed:\n{result.stdout}\n{result.stderr}")

        with open(sol_path) as f:
            report = f.read()

    return parse_solution(report)


def decompose_paths(graph, demands, solution):
    decompositions = []
    for i, demand in enumerate(demands):
        src = demand["src"]
        dst = demand["dst"]

        if src == dst:
            g = solution.get(f"g{i}", 0.0)
            decompositions.append([([src], g)])
            continue

        residual = {u: {} for u in graph}
        for u in graph:
            for edge in graph[u]:
                v = edge["to"]
                flow = solution.get(f"f{i}_{u}_{v}", 0.0)
                if flow > 1e-6:
                    residual[u][v] = flow

        # flow decomposition: repeatedly find a path via BFS, record its bottleneck
        # rate, subtract from residual, until no flow remains
        paths = []
        while True:
            parent = {src: None}
            queue = [src]
            while queue and dst not in parent:
                next_queue = []
                for u in queue:
                    for v, flow in residual[u].items():
                        if flow > 1e-6 and v not in parent:
                            parent[v] = u
                            next_queue.append(v)
                queue = next_queue

            if dst not in parent:
                break

            path = [dst]
            cur = dst
            while cur != src:
                cur = parent[cur]
                path.append(cur)
            path.reverse()

            bottleneck = min(
                residual[path[k]][path[k + 1]] for k in range(len(path) - 1)
            )
            paths.append((path, bottleneck))

            for k in range(len(path) - 1):
                u, v = path[k], path[k + 1]
                residual[u][v] -= bottleneck
                if residual[u][v] <= 1e-6:
                    del residual[u][v]

        decompositions.append(paths)
    return decompositions


def install_base_routing(nodes, subnets, graph):
    router_names = list(graph.keys())
    for subnet_addr, subnet in subnets.items():
        if not subnet["routers"]:
            continue
        dst_r_name = subnet["routers"][0]["name"]
        # reverse BFS from dst_r_name: route[u] = (iface, next_hop) to reach this subnet
        route, queue = {dst_r_name: (None, None)}, [dst_r_name]
        while queue:
            curr = queue.pop(0)
            for u in router_names:
                for e in graph[u]:
                    if e["to"] == curr and u not in route:
                        route[u] = (e["interface"], e["address"])
                        queue.append(u)
        for r_name in router_names:
            if r_name != dst_r_name and r_name in route:
                iface, via = route[r_name]
                nodes[r_name].cmd(f"ip route add {subnet_addr} via {via} dev {iface}")


def install_mpls_rules(nodes, topology, subnets, graph, demands, decompositions):
    link_iface = {
        (r_name, edge["to"]): (edge["interface"], edge["address"])
        for r_name, edges in graph.items()
        for edge in edges
    }

    host_subnet = {
        host["name"]: subnet_addr
        for subnet_addr, subnet in subnets.items()
        for host in subnet["hosts"]
    }

    next_label = 100
    routes = {}

    for i, paths in enumerate(decompositions):
        dst_subnet = host_subnet[topology["demands"][i]["dst"]]
        src_r_name = demands[i]["src"]

        for path, rate in paths:
            n_hops = len(path) - 1
            if n_hops < 1:
                continue

            # one label per hop; labels[0] is added at the source router
            labels = list(range(next_label, next_label + n_hops))
            next_label += n_hops
            ifaces = [link_iface[(path[k], path[k + 1])] for k in range(n_hops)]

            # transit routers: swap in-label to out-label
            for k in range(1, n_hops):
                if_name, next_ip = ifaces[k]
                nodes[path[k]].cmd(
                    f"ip -f mpls route add {labels[k - 1]} as {labels[k]} "
                    f"via inet {next_ip} dev {if_name}"
                )

            # egress: pop last label
            nodes[path[-1]].cmd(f"ip -f mpls route add {labels[-1]} dev lo")

            routes.setdefault((src_r_name, dst_subnet), []).append(
                (rate, labels[0], ifaces[0])
            )

    for (src_r_name, dst_subnet), entries in routes.items():
        if len(entries) == 1:
            _, first_label, (if_name, next_ip) = entries[0]
            nodes[src_r_name].cmd(
                f"ip route replace {dst_subnet} encap mpls {first_label} "
                f"via {next_ip} dev {if_name}"
            )
        else:
            weights = [max(1, int(round(rate * 100))) for rate, _, _ in entries]
            cmd = f"ip route replace {dst_subnet}"
            for (_, first_label, (if_name, next_ip)), w in zip(entries, weights):
                cmd += f" nexthop encap mpls {first_label} via {next_ip} dev {if_name} weight {w}"
            nodes[src_r_name].cmd(cmd)


def start_mininet(topology, subnets, graph, demands, decompositions):
    class Router(Node):
        def config(self, **params):
            super().config(**params)
            self.cmd("sysctl -w net.ipv4.ip_forward=1")
            self.cmd("modprobe mpls_router 2>/dev/null")
            self.cmd("modprobe mpls_iptunnel 2>/dev/null")
            self.cmd("sysctl -w net.mpls.platform_labels=1048575")
            self.cmd("sysctl -w net.mpls.conf.lo.input=1")

        def terminate(self):
            self.cmd("sysctl -w net.ipv4.ip_forward=0")
            super().terminate()

    setLogLevel("info")
    net = Mininet(switch=OVSSwitch, controller=None, link=TCLink)
    nodes = {}

    router_names = set(topology["routers"].keys())

    for subnet in subnets.values():
        for node in subnet["routers"] + subnet["hosts"]:
            name = node["name"]
            if name not in nodes:
                if name in router_names:
                    nodes[name] = net.addHost(name, cls=Router, ip=None)
                else:
                    nodes[name] = net.addHost(name, ip=None)

    switch_id = 1

    for subnet_addr, subnet in subnets.items():
        prefix = subnet_addr.prefixlen
        routers = subnet["routers"]
        hosts = subnet["hosts"]
        all_nodes = routers + hosts

        if subnet["switch"] is None and len(all_nodes) == 2:
            a, b = all_nodes[0], all_nodes[1]
            bw = subnet["cost"] if len(routers) == 2 else None
            net.addLink(
                nodes[a["name"]],
                nodes[b["name"]],
                intfName1=a["interface"],
                intfName2=b["interface"],
                bw=bw,
            )
            nodes[a["name"]].setIP(f"{a['address']}/{prefix}", intf=a["interface"])
            nodes[b["name"]].setIP(f"{b['address']}/{prefix}", intf=b["interface"])
        else:
            sw = net.addSwitch(f"s{switch_id}", failMode="standalone")
            switch_id += 1
            for node in all_nodes:
                net.addLink(nodes[node["name"]], sw, intfName1=node["interface"])
                nodes[node["name"]].setIP(
                    f"{node['address']}/{prefix}", intf=node["interface"]
                )

    net.build()
    net.start()

    for r_name in router_names:
        for intf in nodes[r_name].intfList():
            if intf.name != "lo":
                nodes[r_name].cmd(f"sysctl -w net.mpls.conf.{intf.name}.input=1")

    for subnet in subnets.values():
        if not subnet["hosts"] or not subnet["routers"]:
            continue
        gw_ip = subnet["routers"][0]["address"]
        for host in subnet["hosts"]:
            nodes[host["name"]].cmd(f"ip route add default via {gw_ip}")

    install_base_routing(nodes, subnets, graph)
    install_mpls_rules(nodes, topology, subnets, graph, demands, decompositions)

    CLI(net)
    net.stop()


def main():
    args = parse_command_line()
    do_print = args.print
    do_lp = args.lp
    topology_path = args.definition

    with open(topology_path) as file:
        topology = yaml.safe_load(file)

    subnets = get_subnets(topology)
    graph = get_graph(subnets)

    lp = build_lp(topology, subnets, graph)

    if do_lp:
        print(lp)
        return

    solution = solve_lp(lp)

    if do_print:
        for i, _ in enumerate(topology["demands"]):
            g = solution.get(f"g{i}", 0.0)
            print(f"The best goodput for flow demand #{i + 1} is {g} Mbps")
        return

    demands = get_demands(topology, subnets)
    decompositions = decompose_paths(graph, demands, solution)
    start_mininet(topology, subnets, graph, demands, decompositions)


if __name__ == "__main__":
    main()
