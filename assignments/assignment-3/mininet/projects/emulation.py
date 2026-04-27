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


def get_subnet_address(ip, mask):
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
            for interface, config in interfaces.items():
                subnet_id = get_subnet_address(config["address"], config["mask"])
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


def get_routers_graph(subnets):
    graph = {}

    for subnet in subnets.values():
        routers = subnet["routers"]
        cost = subnet["cost"]
        nodes = routers
        nodes_n = len(nodes)
        for i in range(nodes_n):
            for j in range(nodes_n):
                if i == j:
                    continue
                link = {"to": nodes[j], "cost": cost}
                if nodes[i] not in graph:
                    graph[nodes[i]] = []
                graph[nodes[i]].append(link)

    return graph


def floyd_warshall(graph):
    nodes = sorted(graph.keys())

    dist = {i: {j: float("inf") for j in nodes} for i in nodes}
    next_hop = {i: {j: None for j in nodes} for i in nodes}

    for u in nodes:
        dist[u][u] = 0
        for link in graph[u]:
            v = link["to"]
            cost = link["cost"]
            dist[u][v] = cost
            next_hop[u][v] = v

    for k in nodes:
        for i in nodes:
            for j in nodes:
                # Calculate the cost of the path through node k
                path_through_k = dist[i][k] + dist[k][j]

                # If passing through k is cheaper than the direct route
                if dist[i][j] > path_through_k:
                    dist[i][j] = path_through_k
                    next_hop[i][j] = next_hop[i][k]

    return dist, next_hop


def main():
    result = parse_command_line()
    if result is None:
        sys.exit(1)
    draw, topology_path = result

    with open(topology_path, "r") as file:
        topology = yaml.safe_load(file)

    subnets = get_subnets(topology)
    routers_graph = get_routers_graph(subnets)

    print("h")

    # if draw:
    #     print_routers(adj, edges)
    #     sys.exit(0)


if __name__ == "__main__":
    main()
