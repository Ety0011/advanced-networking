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
        "  -d, --draw output a map of the routers in GraphViz format"
    )


def parse():
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
    mask_bytes = [int(x) for x in mask.split("x")]

    net_bytes = []
    for i in range(4):
        net_bytes.append(str(ip_bytes[i] & mask_bytes[i]))

    return ".".join(net_bytes)


def get_subnets(topology):
    subnets = {}

    for nodes in topology.values():
        for node, interfaces in nodes.items():
            for config in interfaces.values():
                subnet_id = calculate_subnet_address(config["address"], config["mask"])
                if subnet_id not in subnets:
                    subnets[subnet_id] = {"switch": None, "nodes": []}
                cost = config.get("cost", 1)
                subnets[subnet_id]["nodes"].append((node, cost))

    switch_id = 1
    for subnet in subnets.values():
        if len(subnet["nodes"]) > 2:
            subnet["switch"] = f"s{switch_id}"
            switch_id += 1

    return subnets


def get_edges(subnets):
    edges = set()

    for subnet in subnets.values():
        switch = subnet["switch"]
        nodes = subnet["nodes"]
        if switch is not None:
            for name, cost in nodes:
                names = sorted([switch, name])
                edge = (names[0], names[1], cost)
                edges.add(edge)
        else:
            name_a, cost_a = nodes[0]
            name_b, cost_b = nodes[1]
            cost = max(cost_a, cost_b)
            names = sorted([name_a, name_b])
            edge = (names[0], names[1], cost)
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


def main():
    result = parse()

    if result is None:
        sys.exit(1)

    draw, topology_path = result

    with open(topology_path, "r") as file:
        topology = yaml.safe_load(file)


if __name__ == "__main__":
    main()
