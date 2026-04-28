import ipaddress
import sys

import yaml
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch


def print_help():
    print(
        "usage: emulation.py [-h] [-d] definition\n\n"
        "A tool to define the emulation of a network.\n\n"
        "positional arguments:\n"
        "  definition the definition file of the network in YAML\n\n"
        "options:\n"
        "  -h, --help show this help message and exit\n"
        "  -d, --draw output a map of the routers in GraphViz format\n"
    )


def parse_command_line():
    args = sys.argv
    args_count = len(args)
    min_args = 2
    max_args = 3

    if args_count < min_args:
        print("Error: No arguments provided.")
        return None

    if args_count > max_args:
        print("Error: Too many arguments provided.")
        return None

    index = 1
    draw = False

    while index < args_count:
        arg = args[index]

        if arg in ("-h", "--help"):
            print_help()
            return None
        elif arg in ("-d", "--draw"):
            draw = True
        else:
            break

        index += 1

    if index != args_count - 1:
        print("Error: Expected a definition file as the last argument.")
        return None

    return draw, args[index]


def get_subnets(topology):
    subnets = {}

    for category, nodes in topology.items():
        for name, interfaces in nodes.items():
            for interface, config in interfaces.items():
                address = config["address"]
                mask = config["mask"]
                # cool library function discovered from Giovanni Elisei
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


def floyd_warshall(graph):
    names = sorted(graph.keys())

    dist = {i: {j: float("inf") for j in names} for i in names}
    next_hop = {i: {j: None for j in names} for i in names}

    for u in names:
        dist[u][u] = 0
        for link in graph[u]:
            v = link["to"]
            cost = link["cost"]
            # there can be multiple links
            if cost < dist[u][v]:
                dist[u][v] = cost
                next_hop[u][v] = {
                    "address": link["address"],
                    "interface": link["interface"],
                }

    for k in names:
        for i in names:
            for j in names:
                dist_through_k = dist[i][k] + dist[k][j]
                if dist[i][j] > dist_through_k:
                    dist[i][j] = dist_through_k
                    next_hop[i][j] = next_hop[i][k]

    return dist, next_hop


def start_mininet(subnets, dist, next_hop):
    setLogLevel("info")
    mininet = Mininet(topo=None, build=False, switch=OVSSwitch)
    mini_nodes = {}

    # build
    for subnet in subnets.values():
        nodes = subnet["routers"] + subnet["hosts"]
        for node in nodes:
            node_name = node["name"]
            if node_name not in mini_nodes:
                mini_nodes[node_name] = mininet.addHost(node_name)
        switch_name = subnet["switch"]
        if switch_name is not None and switch_name not in mini_nodes:
            mini_nodes[switch_name] = mininet.addSwitch(switch_name)

    # wire up
    for subnet_address, subnet in subnets.items():
        nodes = subnet["routers"] + subnet["hosts"]
        switch_name = subnet["switch"]
        prefix = subnet_address.prefixlen

        if switch_name is None:  # exactly 2 nodes
            src, dst = nodes[0], nodes[1]
            mininet.addLink(
                mini_nodes[src["name"]],
                mini_nodes[dst["name"]],
                intfName1=src["interface"],
                intfName2=dst["interface"],
                params1={"ip": f"{src['address']}/{prefix}"},
                params2={"ip": f"{dst['address']}/{prefix}"},
            )
        else:  # (1 router, 1 switch, multiple hosts)
            for src in nodes:
                mininet.addLink(
                    mini_nodes[src["name"]],
                    mini_nodes[switch_name],
                    intfName1=src["interface"],
                    params1={"ip": f"{src['address']}/{prefix}"},
                )

    mininet.start()

    # add gateways
    for subnet in subnets.values():
        if not subnet["hosts"]:
            continue
        # every host is guaranteed to have one router
        gateway_ip = subnet["routers"][0]["address"]
        for host in subnet["hosts"]:
            mini_host = mini_nodes[host["name"]]
            mini_host.cmd(f"ip route add default via {gateway_ip}")

    # add routing tables
    # for each router, I need to find the closest router on each subnet
    # and then forward next hop towards that router
    router_names = set(next_hop.keys())
    for src_name in router_names:
        mini_nodes[src_name].cmd("sysctl -w net.ipv4.ip_forward=1")
        for subnet_address, subnet in subnets.items():
            # find closest router in subnet
            best_name = None
            best_dist = float("inf")
            for dst in subnet["routers"]:
                dst_name = dst["name"]
                if src_name == dst_name:
                    continue
                dst_dist = dist[src_name][dst_name]
                if dst_dist < best_dist:
                    best_dist = dst_dist
                    best_name = dst_name
            # subnet is unreachable
            if best_name is None:
                continue
            # set table entry
            hop = next_hop[src_name][best_name]
            mini_nodes[src_name].cmd(
                f"ip route add {subnet_address} "
                f"via {hop['address']} "
                f"dev {hop['interface']}"
            )

    # run
    CLI(mininet)
    mininet.stop()


def main():
    result = parse_command_line()
    if result is None:
        sys.exit(1)
    draw, topology_path = result

    with open(topology_path, "r") as file:
        topology = yaml.safe_load(file)

    subnets = get_subnets(topology)

    if draw:
        print_graphviz(subnets)
        sys.exit(0)

    graph = get_graph(subnets)
    dist, next_hop = floyd_warshall(graph)

    start_mininet(subnets, dist, next_hop)


if __name__ == "__main__":
    main()
