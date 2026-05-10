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
    for name in sorted(names):
        print(f"    {name} [shape=circle];")
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
    lines = []
    lines.append("Maximize")

    demands = get_demands(topology, subnets)
    lines.append(" obj: alpha")

    lines.append("Subject to")
    router_names = graph.keys()
    for i, demand in enumerate(demands):
        # flow conservation
        for src_name in router_names:
            outgoing = []
            ingoing = []
            for dst in graph[src_name]:
                outgoing.append(f"f{i}_{src_name}_{dst['to']}")
                ingoing.append(f"f{i}_{dst['to']}_{src_name}")
            if src_name == demand["src"]:
                ingoing.append(f"g{i}")
            elif src_name == demand["dst"]:
                outgoing.append(f"g{i}")
            pos = " + ".join(outgoing)
            neg = " - ".join(ingoing)
            lines.append(" " + (pos + " - " + neg if neg else pos) + " = 0")
        lines.append("")

        lines.append(f" g{i} <= {demand['rate']}")
        lines.append(f" g{i} - {demand['rate']} alpha >= 0")

    # capacity
    for src, edges in graph.items():
        for edge in edges:
            flows = [f"f{i}_{src}_{edge['to']}" for i in range(len(demands))]
            lines.append(" " + " + ".join(flows) + f" <= {edge['cost']}")

    lines.append("Bounds")
    lines.append(" 0 <= alpha <= 1")
    lines.append("End")

    return "\n".join(lines)


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


def parse_solution(report):
    values = {}
    in_columns = False
    past_header = False
    for line in report.splitlines():
        if "Column name" in line:
            in_columns = True
            past_header = False
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
        if len(parts) < 4:
            continue
        try:
            values[parts[1]] = float(parts[3])
        except ValueError:
            continue
    return values


def decompose_paths(graph, demands, solution):
    decompositions = []
    for i, demand in enumerate(demands):
        src_r = demand["src"]
        dst_r = demand["dst"]

        if src_r == dst_r:
            g = solution.get(f"g{i}", 0.0)
            decompositions.append([([src_r], g)])
            continue

        residual = {u: {} for u in graph}
        for u in graph:
            for edge in graph[u]:
                v = edge["to"]
                val = solution.get(f"f{i}_{u}_{v}", 0.0)
                if val > 1e-6:
                    residual[u][v] = val

        paths = []
        while True:
            parent = {src_r: None}
            queue = [src_r]
            while queue and dst_r not in parent:
                nxt = []
                for u in queue:
                    for v, flow in residual[u].items():
                        if flow > 1e-6 and v not in parent:
                            parent[v] = u
                            nxt.append(v)
                queue = nxt

            if dst_r not in parent:
                break

            path = [dst_r]
            cur = dst_r
            while cur != src_r:
                cur = parent[cur]
                path.append(cur)
            path.reverse()

            bottleneck = min(residual[path[k]][path[k + 1]] for k in range(len(path) - 1))
            paths.append((path, bottleneck))

            for k in range(len(path) - 1):
                u, v = path[k], path[k + 1]
                residual[u][v] -= bottleneck
                if residual[u][v] <= 1e-6:
                    del residual[u][v]

        decompositions.append(paths)
    return decompositions


def install_mpls_rules(nodes, topology, subnets, graph, demands, decompositions):
    iface_of = {}
    for src, edges in graph.items():
        for edge in edges:
            iface_of[(src, edge["to"])] = (edge["interface"], edge["address"])

    host_subnet = {}
    for subnet_addr, subnet in subnets.items():
        for host in subnet["hosts"]:
            host_subnet[host["name"]] = subnet_addr

    next_label = 100
    aggregated = {}

    for i, (demand_raw, paths) in enumerate(zip(topology["demands"], decompositions)):
        dst_host = demand_raw["dst"]
        dst_subnet = host_subnet[dst_host]
        src_router = demands[i]["src"]

        for path_nodes, rate in paths:
            n_hops = len(path_nodes) - 1
            if n_hops < 1:
                continue

            labels = list(range(next_label, next_label + n_hops))
            next_label += n_hops
            ifaces = [iface_of[(path_nodes[k], path_nodes[k + 1])] for k in range(n_hops)]

            # transit routers: swap in-label to out-label
            for k in range(1, n_hops):
                router = path_nodes[k]
                if_name, next_ip = ifaces[k]
                nodes[router].cmd(
                    f"ip -f mpls route add {labels[k - 1]} as {labels[k]} "
                    f"via inet {next_ip} dev {if_name}"
                )

            # egress: pop last label
            nodes[path_nodes[-1]].cmd(f"ip -f mpls route add {labels[-1]} dev lo")

            key = (src_router, dst_subnet)
            aggregated.setdefault(key, []).append((rate, labels[0], ifaces[0]))

    for (src_router, dst_subnet), entries in aggregated.items():
        if len(entries) == 1:
            _, first_label, (if_name, next_ip) = entries[0]
            nodes[src_router].cmd(
                f"ip route add {dst_subnet} encap mpls {first_label} "
                f"via {next_ip} dev {if_name}"
            )
        else:
            weights = [max(1, int(round(rate * 100))) for rate, _, _ in entries]
            cmd = f"ip route add {dst_subnet}"
            for (_, first_label, (if_name, next_ip)), w in zip(entries, weights):
                cmd += f" nexthop encap mpls {first_label} via {next_ip} dev {if_name} weight {w}"
            nodes[src_router].cmd(cmd)


def start_mininet(topology, subnets, graph, demands, decompositions):
    class Router(Node):
        def config(self, **params):
            super().config(**params)
            self.cmd("sysctl -w net.ipv4.ip_forward=1")
            self.cmd("modprobe mpls_router 2>/dev/null")
            self.cmd("modprobe mpls_iptunnel 2>/dev/null")
            self.cmd("sysctl -w net.mpls.platform_labels=1048575")

        def terminate(self):
            self.cmd("sysctl -w net.ipv4.ip_forward=0")
            super().terminate()

    setLogLevel("info")
    net = Mininet(switch=OVSSwitch, controller=None, link=TCLink)
    nodes = {}

    router_names = set(topology["routers"].keys())

    # create nodes
    for subnet in subnets.values():
        for node in subnet["routers"] + subnet["hosts"]:
            name = node["name"]
            if name not in nodes:
                if name in router_names:
                    nodes[name] = net.addHost(name, cls=Router, ip=None)
                else:
                    nodes[name] = net.addHost(name, ip=None)

    switch_id = 1

    # wire up
    for subnet_addr, subnet in subnets.items():
        prefix = subnet_addr.prefixlen
        routers = subnet["routers"]
        hosts = subnet["hosts"]
        all_nodes = routers + hosts

        if subnet["switch"] is None and len(all_nodes) == 2:
            a, b = all_nodes[0], all_nodes[1]
            bw = subnet["cost"] if routers and len(routers) == 2 else None
            kw = {"bw": bw} if bw else {}
            net.addLink(
                nodes[a["name"]], nodes[b["name"]],
                intfName1=a["interface"], intfName2=b["interface"],
                **kw,
            )
            nodes[a["name"]].setIP(f"{a['address']}/{prefix}", intf=a["interface"])
            nodes[b["name"]].setIP(f"{b['address']}/{prefix}", intf=b["interface"])
        else:
            sw_name = f"s{switch_id}"
            switch_id += 1
            sw = net.addSwitch(sw_name, failMode="standalone")
            switches[sw_name] = sw
            for node in all_nodes:
                net.addLink(nodes[node["name"]], sw, intfName1=node["interface"])
                nodes[node["name"]].setIP(
                    f"{node['address']}/{prefix}", intf=node["interface"]
                )

    net.build()
    net.start()

    # enable MPLS input on all router interfaces
    for r_name in router_names:
        for intf in nodes[r_name].intfList():
            if intf.name != "lo":
                nodes[r_name].cmd(f"sysctl -w net.mpls.conf.{intf.name}.input=1")

    # host default gateways
    for subnet in subnets.values():
        if not subnet["hosts"] or not subnet["routers"]:
            continue
        gw_ip = subnet["routers"][0]["address"]
        for host in subnet["hosts"]:
            nodes[host["name"]].cmd(f"ip route add default via {gw_ip}")

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

    # do_lp -> just print lp definition
    lp = build_lp(topology, subnets, graph)

    if do_lp:
        print(lp)
        return

    solution = solve_lp(lp)

    if do_print:
        for i, _ in enumerate(topology["demands"]):
            g = solution.get(f"g{i}", 0.0)
            g_str = str(int(round(g))) if abs(g - round(g)) < 1e-6 else f"{g:.4g}"
            print(f"The best goodput for flow demand #{i + 1} is {g_str} Mbps")
        return

    demands = get_demands(topology, subnets)
    decompositions = decompose_paths(graph, demands, solution)
    start_mininet(topology, subnets, graph, demands, decompositions)


if __name__ == "__main__":
    main()
