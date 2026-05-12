# Reused as-is or with minor changes from my previous assignment (emulation.py):
#   parse_args (extended), subnet_of, collect_subnets, link_cost,
#   the Router class, and the link-creation logic inside run_mininet.
#
# References used:
#   - https://mininet.org/api/index.html for the Mininet API
#   - https://docs.python.org/3/library/ipaddress.html for the ipaddress module
#   - https://www.gnu.org/software/glpk/ and the GLPK reference manual
#     for the CPLEX LP file format and glpsol output format
#   - man pages of `ip route`, `ip -f mpls route` and `tc` for the MPLS / rate
#     limiting setup
#
# I discussed the structure of the LP with my classmate Etienne Orio,
# in particular how to model max-min fairness with a single auxiliary
# variable alpha and per-link, per-demand flow variables.
#
# Known limitations:
#   - The path decomposition for splittable flows uses a simple greedy
#     algorithm. It always finds a valid decomposition but it may produce
#     more sub-paths than strictly necessary.
#   - The solver is invoked through subprocess and we parse the textual
#     output of glpsol; if the format of glpsol changes the parsing
#     might need to be adapted.

import argparse
import ipaddress
import os
import subprocess
import sys
import tempfile

import yaml
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Node, OVSKernelSwitch

# Mininet is only needed when we actually build the emulation, so we import
# it lazily inside run_mininet(). This way --lp and --print work even on
# machines where Mininet is not installed.


# ---------------------------------------------------------------------------
# Argument parsing  (REUSED and extended from emulation.py)
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="A tool to define the emulation of a network configured "
        "to achieve the best overall goodput under a given set "
        "of flow demands."
    )
    parser.add_argument(
        "definition",
        help="the definition file of the network and flow demands in YAML",
    )
    parser.add_argument(
        "-p",
        "--print",
        action="store_true",
        dest="print_goodputs",
        help="print the optimal goodput for each flow and exit",
    )
    parser.add_argument(
        "-l",
        "--lp",
        action="store_true",
        help="print the definition of the optimization problem in CPLEX LP format",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Topology parsing  (REUSED from emulation.py)
# ---------------------------------------------------------------------------
def subnet_of(address, mask):
    # REUSED from emulation.py
    return ipaddress.IPv4Network(f"{address}/{mask}", strict=False)


def collect_subnets(topology):
    # REUSED from emulation.py: groups all interfaces by the subnet they
    # belong to. Each entry is
    #   (node_name, if_name, ip, mask, cost, is_router)
    subnets = {}

    for router_name, interfaces in topology["routers"].items():
        for if_name, if_data in interfaces.items():
            net = subnet_of(if_data["address"], if_data["mask"])
            entry = (
                router_name,
                if_name,
                if_data["address"],
                if_data["mask"],
                if_data.get("cost"),
                True,
            )
            subnets.setdefault(net, []).append(entry)

    for hostname, interfaces in topology["hosts"].items():
        for if_name, if_data in interfaces.items():
            net = subnet_of(if_data["address"], if_data["mask"])
            entry = (
                hostname,
                if_name,
                if_data["address"],
                if_data["mask"],
                if_data.get("cost"),
                False,
            )
            subnets.setdefault(net, []).append(entry)

    return subnets


def link_cost(members):
    # REUSED from emulation.py. In this assignment "cost" is actually the
    # capacity of the link in Mbps (the wording in the assignment says
    # so explicitly). The default of 1Mbps comes from the assignment text.
    for _, _, _, _, cost, _ in members:
        if cost is not None:
            return cost
    return 1


# ---------------------------------------------------------------------------
# Helpers tailored to this assignment
# ---------------------------------------------------------------------------
def host_gateway_router(subnets, hostname):
    """Return the (router_name, router_if, router_ip) that is the gateway
    of `hostname`. The assignment guarantees that each host shares a subnet
    with exactly one router interface, so the answer is well-defined."""
    for members in subnets.values():
        host_entry = None
        router_entry = None
        for m in members:
            name, if_name, ip, _, _, is_r = m
            if name == hostname and not is_r:
                host_entry = m
            if is_r:
                router_entry = m
        if host_entry is not None and router_entry is not None:
            r_name, r_if, r_ip, _, _, _ = router_entry
            return r_name, r_if, r_ip
    # Should never happen on a valid input
    return None


def router_links(subnets):
    """Build the inter-router topology used by the LP.

    A "link" here is a directed router-to-router link. For each subnet that
    contains two or more routers we create one directed link in each
    direction, but the two directions share a single capacity (the cost of
    the link in Mbps). We return a list of tuples
        (link_id, from_router, to_router, undirected_id, capacity, from_if, to_ip)
    where `undirected_id` is the same for the two directions of the same
    physical link (so we can write a single capacity constraint that sums
    the flow in both directions).
    """
    links = []
    link_id = 0
    undirected_id = 0
    for subnet, members in subnets.items():
        routers = [m for m in members if m[5]]
        if len(routers) < 2:
            # subnet only contains hosts/one router => not a router-router link
            continue
        cap = link_cost(members)
        # one undirected pair = one capacity. We assume point-to-point
        # router-to-router links (the assignment guarantees this).
        for i in range(len(routers)):
            for j in range(i + 1, len(routers)):
                a_name, a_if, a_ip, _, _, _ = routers[i]
                b_name, b_if, b_ip, _, _, _ = routers[j]
                links.append((link_id, a_name, b_name, undirected_id, cap, a_if, b_ip))
                link_id += 1
                links.append((link_id, b_name, a_name, undirected_id, cap, b_if, a_ip))
                link_id += 1
                undirected_id += 1
    return links


def all_routers(subnets):
    return sorted(
        {
            name
            for members in subnets.values()
            for (name, _, _, _, _, is_r) in members
            if is_r
        }
    )


# ---------------------------------------------------------------------------
# LP construction
# ---------------------------------------------------------------------------
# Variable naming convention:
#   alpha            : the minimum effectiveness ratio (objective)
#   f_<i>_<lid>      : flow of demand i over directed link lid (in Mbps)
#   g_<i>            : goodput of demand i (in Mbps)
#
# Demand i has source router S_i (gateway of the source host) and
# destination router D_i (gateway of the destination host).
#
# Constraints:
#   * capacity of every directed link  : sum_i f_i_lid <= cap(lid)
#   * flow conservation at every router u, every demand i:
#         sum_{lid out of u} f_i_lid - sum_{lid into u} f_i_lid =
#             +g_i  if u == S_i
#             -g_i  if u == D_i
#              0    otherwise
#   * goodput is at most the requested rate  : g_i <= r_i
#   * effectiveness                          : g_i >= alpha * r_i
#                                       i.e. g_i - alpha*r_i >= 0
#   * 0 <= alpha <= 1
#   * f, g >= 0
def build_lp(subnets, demands):
    routers = all_routers(subnets)
    links = router_links(subnets)

    # Pre-compute, for every router and every link, whether the link goes out
    # of or into that router. This makes the flow-conservation constraints
    # easy to write.
    out_of = {r: [] for r in routers}
    into = {r: [] for r in routers}
    for lid, a, b, _, _, _, _ in links:
        out_of[a].append(lid)
        into[b].append(lid)

    # Group directed link IDs by the undirected link they belong to, so we
    # can write one shared capacity constraint per physical link.
    undirected = {}  # uid -> (cap, [list of directed link ids])
    for lid, a, b, uid, cap, _, _ in links:
        entry = undirected.setdefault(uid, (cap, []))
        entry[1].append(lid)

    # Resolve the source/destination routers of every demand
    demand_endpoints = []
    for d in demands:
        src_r = host_gateway_router(subnets, d["src"])[0]
        dst_r = host_gateway_router(subnets, d["dst"])[0]
        demand_endpoints.append((src_r, dst_r, d["rate"]))

    lines = []
    lines.append("Maximize")
    lines.append(" obj: alpha")

    lines.append("Subject To")

    cnum = 0  # constraint counter (used to generate unique constraint names)

    # --- capacity constraints, one per undirected link ---
    # The two directions of a physical link share the same capacity, so the
    # sum of the flow in BOTH directions over all demands must not exceed
    # the link's cost.
    for uid in sorted(undirected.keys()):
        cap, lids = undirected[uid]
        terms = []
        for lid in lids:
            for i in range(len(demands)):
                terms.append(f"f_{i}_{lid}")
        cnum += 1
        lines.append(f" c{cnum}: {' + '.join(terms)} <= {cap}")

    # --- flow conservation, one per (demand, router) ---
    for i, (src_r, dst_r, rate) in enumerate(demand_endpoints):
        # special case: source and destination share the same gateway router.
        # The traffic does not traverse the routed network at all so the
        # goodput is simply min(rate, rate) = rate. We pin g_i = r_i.
        if src_r == dst_r:
            cnum += 1
            lines.append(f" c{cnum}: g_{i} = {rate}")
            continue

        for u in routers:
            out_terms = [f"f_{i}_{lid}" for lid in out_of[u]]
            in_terms = [f"f_{i}_{lid}" for lid in into[u]]

            # Build: (sum out) - (sum in) = rhs
            # Implemented as out terms positive, in terms negative.
            expr_parts = []
            expr_parts.extend(out_terms)
            expr_parts.extend(f"- {t}" for t in in_terms)
            if not expr_parts:
                # Router with no router-to-router links: skip (no variables).
                continue
            # Join into a clean LP expression.
            expr = expr_parts[0]
            for p in expr_parts[1:]:
                expr += f" + {p}" if not p.startswith("-") else f" {p}"

            cnum += 1
            if u == src_r:
                # net out = +g_i  ->  expr - g_i = 0
                lines.append(f" c{cnum}: {expr} - g_{i} = 0")
            elif u == dst_r:
                # net out = -g_i  ->  expr + g_i = 0
                lines.append(f" c{cnum}: {expr} + g_{i} = 0")
            else:
                lines.append(f" c{cnum}: {expr} = 0")

    # --- goodput cap and effectiveness ratio constraints ---
    for i, (_, _, rate) in enumerate(demand_endpoints):
        cnum += 1
        lines.append(f" c{cnum}: g_{i} <= {rate}")
        cnum += 1
        # g_i - alpha*r_i >= 0
        lines.append(f" c{cnum}: g_{i} - {rate} alpha >= 0")

    # --- bounds ---
    # In CPLEX LP format, all variables default to [0, +inf), so we only
    # need to state alpha's upper bound explicitly. We list it explicitly
    # to make the LP self-explanatory.
    lines.append("Bounds")
    lines.append(" 0 <= alpha <= 1")

    lines.append("End")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Solving the LP via glpsol
# ---------------------------------------------------------------------------
def solve_lp(lp_text):
    """Run glpsol on the given LP text and parse its solution.

    Returns a dict {variable_name: value}.
    """
    # We write the LP and the desired output file in a temporary directory
    # and let glpsol produce a plain-text solution file that we then parse.
    with tempfile.TemporaryDirectory() as tmp:
        lp_path = os.path.join(tmp, "problem.lp")
        sol_path = os.path.join(tmp, "problem.sol")

        with open(lp_path, "w") as f:
            f.write(lp_text)

        # --lp tells glpsol to expect CPLEX LP format
        # -o produces a printable solution report
        result = subprocess.run(
            ["glpsol", "--lp", lp_path, "-o", sol_path], capture_output=True, text=True
        )
        if result.returncode != 0:
            sys.stderr.write(result.stdout)
            sys.stderr.write(result.stderr)
            raise RuntimeError("glpsol failed")

        with open(sol_path) as f:
            report = f.read()

    return parse_glpsol_report(report)


def parse_glpsol_report(report):
    """Parse the solution report produced by `glpsol -o`.

    The relevant section looks like:

       No. Column name       St   Activity     Lower bound   Upper bound
       ------ ------------    -- ------------- ------------- -------------
            1 alpha           B       0.66...               0             1
            2 g_0             B       8
            ...

    We extract the column name and its activity (the optimal value).
    """
    values = {}
    in_columns = False
    header_seen = False
    for line in report.splitlines():
        if "Column name" in line:
            in_columns = True
            header_seen = False
            continue
        if not in_columns:
            continue
        if line.strip().startswith("-"):
            header_seen = True
            continue
        if not header_seen:
            continue
        if line.strip() == "" or line.startswith("Karush"):
            # end of the columns section
            break
        # Parse the line. Columns are aligned, but using split() on whitespace
        # is fine because our variable names contain no spaces.
        parts = line.split()
        if len(parts) < 4:
            continue
        # Layout:
        #   <num> <name> <st> <activity> ...
        # For non-basic variables glpsol may insert an extra '*' or similar,
        # but the activity is always parts[3] in our case.
        try:
            name = parts[1]
            activity = float(parts[3])
        except (ValueError, IndexError):
            continue
        values[name] = activity
    return values


# ---------------------------------------------------------------------------
# Path decomposition from the LP solution
# ---------------------------------------------------------------------------
def decompose_paths(subnets, demands, solution):
    """For each demand decompose its flow into a list of (path, rate) where
    `path` is a list of router names from source router to destination router.

    Greedy decomposition: while there is still flow assigned to the demand,
    find any path from source to destination along edges with positive
    remaining flow, push the bottleneck along it, subtract, and record it.
    """
    routers = all_routers(subnets)
    links = router_links(subnets)

    # Build per-demand residual flow on each directed link
    decompositions = []
    for i, d in enumerate(demands):
        src_r = host_gateway_router(subnets, d["src"])[0]
        dst_r = host_gateway_router(subnets, d["dst"])[0]

        if src_r == dst_r:
            # Trivial: "path" of length 0; the goodput is just g_i.
            g = solution.get(f"g_{i}", 0.0)
            decompositions.append([(([src_r]), g)])
            continue

        # remaining[lid] = current residual flow of demand i on link lid
        remaining = {}
        for lid, _, _, _, _, _, _ in links:
            v = solution.get(f"f_{i}_{lid}", 0.0)
            if v > 1e-6:
                remaining[lid] = v

        # adjacency rebuilt from the surviving links each time we look for a path
        link_info = {lid: (a, b) for (lid, a, b, _, _, _, _) in links}

        paths = []
        while remaining:
            # BFS from src_r to dst_r over links with remaining > 0
            parent = {src_r: (None, None)}  # node -> (prev_node, lid_used)
            queue = [src_r]
            while queue and dst_r not in parent:
                nxt = []
                for u in queue:
                    for lid, val in remaining.items():
                        a, b = link_info[lid]
                        if a == u and b not in parent and val > 1e-6:
                            parent[b] = (u, lid)
                            nxt.append(b)
                queue = nxt
            if dst_r not in parent:
                break  # no more paths

            # Reconstruct path and its bottleneck
            path_nodes = [dst_r]
            path_links = []
            cur = dst_r
            while cur != src_r:
                prev, lid = parent[cur]
                path_links.append(lid)
                path_nodes.append(prev)
                cur = prev
            path_nodes.reverse()
            path_links.reverse()
            bottleneck = min(remaining[lid] for lid in path_links)
            paths.append((path_nodes, bottleneck))
            for lid in path_links:
                remaining[lid] -= bottleneck
                if remaining[lid] <= 1e-6:
                    del remaining[lid]
        decompositions.append(paths)
    return decompositions


# ---------------------------------------------------------------------------
# Mininet emulation
# ---------------------------------------------------------------------------
def run_mininet(subnets, demands, decompositions):
    """Build the Mininet emulation, set link capacities, and install MPLS
    rules so that each demand follows the path(s) chosen by the LP.
    """

    class Router(Node):
        """Tiny router node that turns on IP forwarding and enables the MPLS
        kernel modules so we can install MPLS routes via `ip -f mpls route`."""

        # Adapted from the Router class in emulation.py

        def config(self, **params):
            super().config(**params)
            self.cmd("sysctl -w net.ipv4.ip_forward=1")
            # Enable MPLS in the kernel (most stock kernels need these knobs).
            self.cmd("modprobe mpls_router 2>/dev/null")
            self.cmd("modprobe mpls_iptunnel 2>/dev/null")
            self.cmd("sysctl -w net.mpls.platform_labels=1048575")

        def terminate(self):
            self.cmd("sysctl -w net.ipv4.ip_forward=0")
            super().terminate()

    setLogLevel("info")
    net = Mininet(switch=OVSKernelSwitch, controller=None, link=TCLink)

    # Step 1 - create router/host nodes
    nodes = {}
    host_gateway = {}
    for members in subnets.values():
        for name, _, _, _, _, is_router in members:
            if name in nodes:
                continue
            if is_router:
                nodes[name] = net.addHost(name, cls=Router, ip=None)
            else:
                nodes[name] = net.addHost(name, ip=None)

    # Step 2 - create links and assign IPs.
    # This block is essentially REUSED from emulation.py, with the added bit
    # that on each router-to-router link we also set the bandwidth in Mbps
    # to match the link cost (using TCLink's bw= parameter).
    switch_id = 1
    # We need to remember, for every directed (a -> b) router link, which
    # local interface name a uses and which IP b is reachable on. These are
    # consumed when we install MPLS rules.
    iface_of = {}  # (router, neighbour_router) -> (if_name, neighbour_ip)
    for subnet, members in subnets.items():
        routers = [m for m in members if m[5]]
        hosts = [m for m in members if not m[5]]
        prefix = subnet.prefixlen

        if hosts and routers:
            gw_ip = routers[0][2]
            for hostname, _, _, _, _, _ in hosts:
                host_gateway[hostname] = gw_ip

        if not hosts and len(routers) == 2:
            # point-to-point router link, with bandwidth = link cost
            a_name, a_if, a_ip, _, _, _ = routers[0]
            b_name, b_if, b_ip, _, _, _ = routers[1]
            cap = link_cost(members)
            net.addLink(
                nodes[a_name], nodes[b_name], intfName1=a_if, intfName2=b_if, bw=cap
            )
            nodes[a_name].setIP(f"{a_ip}/{prefix}", intf=a_if)
            nodes[b_name].setIP(f"{b_ip}/{prefix}", intf=b_if)
            iface_of[(a_name, b_name)] = (a_if, b_ip)
            iface_of[(b_name, a_name)] = (b_if, a_ip)
        else:
            # subnet with hosts (and possibly multiple routers): switch
            sw = net.addSwitch(f"s{switch_id}", failMode="standalone")
            switch_id += 1
            for name, if_name, ip, _, _, _ in members:
                net.addLink(nodes[name], sw, intfName1=if_name)
                nodes[name].setIP(f"{ip}/{prefix}", intf=if_name)

    net.build()
    net.start()

    # Step 3 - enable MPLS forwarding on every router interface.
    # `net.mpls.conf.<iface>.input` must be 1 for the interface to accept
    # incoming MPLS-encapsulated packets.
    for r_name in all_routers(subnets):
        node = nodes[r_name]
        # Turn on MPLS input on every interface this router has
        for intf in node.intfList():
            if intf.name == "lo":
                continue
            node.cmd(f"sysctl -w net.mpls.conf.{intf.name}.input=1")

    # Step 4 - install MPLS routes.
    #
    # Strategy: for every (demand, path) we allocate one MPLS LSP. On the
    # ingress router we install an `ip route` that pushes the LSP's first
    # label towards the destination subnet of the demand. Every transit
    # router installs an `ip -f mpls route` that swaps the incoming label
    # for the next label and forwards on the appropriate interface. The
    # egress router pops the label and routes by IP.
    #
    # If a demand is split across multiple paths we use Linux multipath
    # routing with weights proportional to the LP-assigned rates, so that
    # ECMP/hash-based balancing approximates the desired split.
    install_mpls_rules(nodes, subnets, demands, decompositions, iface_of)

    CLI(net)
    net.stop()


def install_mpls_rules(nodes, subnets, demands, decompositions, iface_of):
    next_label = 100  # start labels from a "clean" range
    # For convenience: which subnet does each host live in?
    host_subnet = {}
    for subnet, members in subnets.items():
        for name, _, _, _, _, is_r in members:
            if not is_r:
                host_subnet[name] = subnet

    # We may have multiple demands sharing the same source-router /
    # destination-subnet pair (e.g. h1->h4 and h2->h4 if h1 and h2 are on
    # the same subnet). We can only have one IP route per (router, subnet)
    # so we aggregate all paths for the same (src_router, dst_subnet) and
    # install one multipath rule that sums their LP rates.
    aggregated = {}  # (src_router, dst_subnet) -> list of (rate, labels[], ifaces[])

    for i, (d, paths) in enumerate(zip(demands, decompositions)):
        if not paths:
            continue
        src_host = d["src"]
        dst_host = d["dst"]
        dst_subnet = host_subnet[dst_host]
        src_router = host_gateway_router(subnets, src_host)[0]

        # For each path of this demand allocate MPLS labels and install
        # the transit+egress label rules immediately.
        for path_nodes, rate in paths:
            if len(path_nodes) <= 1:
                # source and destination share the gateway -> no MPLS needed
                continue
            labels = [next_label + k for k in range(len(path_nodes) - 1)]
            next_label += len(path_nodes) - 1
            ifaces = []
            for k in range(len(path_nodes) - 1):
                a, b = path_nodes[k], path_nodes[k + 1]
                ifaces.append(iface_of[(a, b)])  # (if_name, neighbour_ip)

            # Transit hops: swap labels[k-1] -> labels[k]
            for k in range(1, len(path_nodes) - 1):
                router = path_nodes[k]
                in_label = labels[k - 1]
                out_label = labels[k]
                if_name, next_ip = ifaces[k]
                nodes[router].cmd(
                    f"ip -f mpls route add {in_label} as {out_label} "
                    f"via inet {next_ip} dev {if_name}"
                )
            # Egress: pop the last label and let normal IP routing deliver
            egress = path_nodes[-1]
            last_label = labels[-1]
            nodes[egress].cmd(f"ip -f mpls route add {last_label} dev lo")

            aggregated.setdefault((src_router, dst_subnet), []).append(
                (rate, labels, ifaces)
            )

    # Now install one ingress rule per aggregated (src_router, dst_subnet).
    for (src_router, dst_subnet), entries in aggregated.items():
        # Convert rates to integer weights for `ip route`. We multiply each
        # rate by 100 and round, with a minimum of 1.
        weights = [max(1, int(round(rate * 100))) for (rate, _, _) in entries]

        if len(entries) == 1:
            rate, labels, ifaces = entries[0]
            first_label = labels[0]
            if_name, next_ip = ifaces[0]
            nodes[src_router].cmd(
                f"ip route add {dst_subnet} "
                f"encap mpls {first_label} via {next_ip} dev {if_name}"
            )
        else:
            # Multipath: one nexthop per path, with weights proportional
            # to the LP-assigned rates.
            cmd = f"ip route add {dst_subnet}"
            for (_, labels, ifaces), w in zip(entries, weights):
                first_label = labels[0]
                if_name, next_ip = ifaces[0]
                cmd += (
                    f" nexthop encap mpls {first_label} "
                    f"via {next_ip} dev {if_name} weight {w}"
                )
            nodes[src_router].cmd(cmd)


# ---------------------------------------------------------------------------
# Top-level
# ---------------------------------------------------------------------------
def main():
    args = parse_args()

    with open(args.definition) as f:
        topology = yaml.safe_load(f)

    subnets = collect_subnets(topology)
    demands = topology.get("demands", [])

    lp_text = build_lp(subnets, demands)

    if args.lp:
        sys.stdout.write(lp_text)
        return

    # Both --print and the default emulation mode need the actual solution.
    solution = solve_lp(lp_text)

    if args.print_goodputs:
        for i in range(len(demands)):
            g = solution.get(f"g_{i}", 0.0)
            # Format: integer if it is one, otherwise a few decimals.
            if abs(g - round(g)) < 1e-6:
                g_str = f"{int(round(g))}"
            else:
                g_str = f"{g:.4g}"
            print(f"The best goodput for flow demand #{i + 1} is {g_str} Mbps")
        return

    decompositions = decompose_paths(subnets, demands, solution)
    run_mininet(subnets, demands, decompositions)


if __name__ == "__main__":
    main()
