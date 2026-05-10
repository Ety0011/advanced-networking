import argparse
import ipaddress

import yaml
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch


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


def print_lp_definition(topology, subnets, graph):
    print("Maximize")

    demands = [
        {
            "src": host_to_router(demand["src"], topology, subnets),
            "dst": host_to_router(demand["dst"], topology, subnets),
            "rate": demand["rate"],
        }
        for demand in topology["demands"]
    ]
    print("obj: alpha")

    print("Subject to")
    incoming_names = {r: [] for r in graph}
    for src, edges in graph.items():
        for edge in edges:
            incoming_names[edge["to"]].append(src)
    router_names = graph.keys()
    for i, demand in enumerate(demands):
        # flow conservation
        for src_name in router_names:
            # src -> outgoing - ingoing = goodput
            # dst -> outgoing - ingoing = -goodput
            # intermediate -> outgoing - ingoing = 0
            outgoing = [f"f{i}_{src_name}_{dst['to']}" for dst in graph[src_name]]
            ingoing = [
                f"f{i}_{dst_name}_{src_name}" for dst_name in incoming_names[src_name]
            ]
            if src_name == demand["src"]:
                ingoing.append(f"g{i}")
            elif src_name == demand["dst"]:
                outgoing.append(f"g{i}")
            pos = " + ".join(outgoing)
            neg = " - ".join(ingoing)
            constraint = (pos + " - " + neg if neg else pos) + " = 0"
            print(constraint)
        print()

        # demand, thank god its just one source for demand
        print(f"g{i} <= {demand['rate']}")

        # effectiveness
        print(f"g{i} - {demand['rate']} alpha >= 0")

    # capacity
    for src, edges in graph.items():
        for edge in edges:
            flows = []
            for i in range(len(demands)):
                flows.append(f"f{i}_{src}_{edge['to']}")
            capacity = " + ".join(flows) + f" <= {edge['cost']}"
            print(capacity)

    # bounds
    print("Bounds")
    print("0 <= alpha <= 1")

    # end
    print("End")


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
                mini_nodes[node_name] = mininet.addHost(node_name, ip=None)
        switch_name = subnet["switch"]
        if switch_name is not None and switch_name not in mini_nodes:
            mini_nodes[switch_name] = mininet.addSwitch(
                switch_name, failMode="standalone"
            )

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
    args = parse_command_line()
    do_print = args.print
    do_lp = args.lp
    topology_path = args.definition

    with open(topology_path) as file:
        topology = yaml.safe_load(file)

    subnets = get_subnets(topology)
    graph = get_graph(subnets)

    # do_lp -> just print lp definition
    if do_lp:
        print_lp_definition(topology, subnets, graph)

    # do_print -> run solver

    # otherwise run mininet


if __name__ == "__main__":
    main()
