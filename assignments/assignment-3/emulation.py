import sys

import yaml


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


def print_routers(adj, edges):
    router_nodes = [node for node in adj if node.startswith("r")]
    router_edges = [edge for edge in edges if edge[0].startswith("r")]

    print("graph Network {")

    for node in router_nodes:
        print(f"    {node} [shape=circle];")

    for edge in router_edges:
        print(f'    {edge[0]} -- {edge[1]} [label="{edge[2]}"];')

    print("}")


def parse_command_line():
    args = sys.argv
    args_count = len(args)
    min_args = 2
    max_args = 4

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

        if arg == "--help":
            print_help()
            return None
        elif arg == "--draw":
            draw = True
        else:
            break

        index += 1

    if index != args_count - 1:
        return None

    return draw, args[index]


def calculate_subnet_address(ip, mask):
    ip_bytes = [int(x) for x in ip.split(".")]
    mask_bytes = [int(x) for x in mask.split(".")]

    net_bytes = []
    for i in range(4):
        net_bytes.append(str(ip_bytes[i] & mask_bytes[i]))

    return ".".join(net_bytes)


def get_subnets(topology):
    subnets = {}

    for category, nodes in topology.items():
        for node, interfaces in nodes.items():
            for config in interfaces.values():
                subnet_id = calculate_subnet_address(config["address"], config["mask"])
                if subnet_id not in subnets:
                    subnets[subnet_id] = {
                        "routers": [],
                        "hosts": [],
                        "switch": None,
                        "cost": 1,
                    }
                cost = config.get("cost", 1)
                if cost > subnets[subnet_id]["cost"]:
                    subnets[subnet_id]["cost"] = cost
                subnets[subnet_id][category].append(node)

    switch_id = 1
    for subnet in subnets.values():
        if len(subnet["hosts"]) >= 2:
            subnet["switch"] = f"s{switch_id}"
            switch_id += 1

    return subnets


def get_edges(subnets):
    edges = set()

    for subnet in subnets.values():
        routers = subnet["routers"]
        hosts = subnet["hosts"]
        switch = subnet["switch"]
        cost = subnet["cost"]
        if len(hosts) == 0:  # only routers
            routers_n = len(routers)
            for i in range(routers_n):
                for j in range(i + 1, routers_n):
                    edge = (routers[i], routers[j], cost)
                    edges.add(edge)
        elif len(hosts) == 1:  # router is guaranteed here
            edge = (routers[0], hosts[0], cost)
            edges.add(edge)
        else:  # hosts > 1 -> there is switch
            all_nodes = routers + hosts
            for node in all_nodes:
                edge = (switch, node, cost)
                edges.add(edge)

    return edges


def get_adjecency(edges):
    adj = {}

    for node_a, node_b, cost in edges:
        if node_a not in adj:
            adj[node_a] = []
        if node_b not in adj:
            adj[node_b] = []
        adj[node_a].append((node_b, cost))
        adj[node_b].append((node_a, cost))

    return adj


def parse_topology(topology):
    subnets = get_subnets(topology)
    edges = get_edges(subnets)
    adj = get_adjecency(edges)
    return adj, edges


def main():
    result = parse_command_line()
    if result is None:
        sys.exit(1)
    draw, topology_path = result

    with open(topology_path, "r") as file:
        topology = yaml.safe_load(file)
    adj, edges = parse_topology(topology)

    if draw:
        print_routers(adj, edges)
        sys.exit(0)


if __name__ == "__main__":
    main()
