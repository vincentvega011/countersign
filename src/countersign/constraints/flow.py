"""Maximal flow for `checkout.line_items` (vendored `checkout_mandate.md`, "Line Items").

The spec's evaluation: each `items` requirement has a quantity; a checkout item matches a
requirement if its id is among the revealed `acceptable_items`; no requirement and no checkout unit
is used twice. The constraint is met when the maximal flow equals both the total required quantity
and the total checkout quantity. Edmonds-Karp on integer capacities; its running time does not
depend on the capacity values, so a huge quantity cannot make it slow.
"""

from __future__ import annotations

from collections import deque


def max_flow(demands: list[int], supplies: list[int], edges: set[tuple[int, int]]) -> int:
    """Flow from requirements (capacity `demands[i]`) to checkout items (`supplies[j]`).

    `edges` holds `(i, j)` pairs with unlimited capacity. Node 0 is the source, then the
    requirements, then the checkout items, then the sink.
    """
    n, m = len(demands), len(supplies)
    source, sink = 0, 1 + n + m
    capacity: dict[int, dict[int, int]] = {v: {} for v in range(sink + 1)}

    def add(u: int, v: int, c: int) -> None:
        capacity[u][v] = capacity[u].get(v, 0) + c
        capacity[v].setdefault(u, 0)

    unlimited = sum(demands) + sum(supplies) + 1
    for i, d in enumerate(demands):
        add(source, 1 + i, d)
    for j, s in enumerate(supplies):
        add(1 + n + j, sink, s)
    for i, j in edges:
        add(1 + i, 1 + n + j, unlimited)

    total = 0
    while True:
        parent = {source: source}
        queue = deque([source])
        while queue and sink not in parent:
            u = queue.popleft()
            for v, c in capacity[u].items():
                if c > 0 and v not in parent:
                    parent[v] = u
                    queue.append(v)
        if sink not in parent:
            return total
        bottleneck, v = unlimited, sink
        while v != source:
            bottleneck = min(bottleneck, capacity[parent[v]][v])
            v = parent[v]
        v = sink
        while v != source:
            capacity[parent[v]][v] -= bottleneck
            capacity[v][parent[v]] += bottleneck
            v = parent[v]
        total += bottleneck
