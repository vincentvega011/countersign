"""Legitimate purchases: the other half of the evaluation.

An attack case asks whether money can move when it must not. A task asks the opposite: when the
customer really signed, does the purchase complete, how fast, and does Countersign block it by mistake
(a false block)? Each task buys real catalog items through the whole app over the PayPal simulator. A
task completes when PayPal holds exactly one capture for exactly the signed total and the judge finds
no violation. The verdict never reads a response body.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from countersign.catalog.catalog import load_catalog

Kind = Literal["autonomous", "human_present"]


@dataclass(frozen=True)
class Task:
    id: str
    description: str
    kind: Kind
    lines: tuple[tuple[str, int], ...]  # (catalog item id, quantity)
    budget: int | None = None  # the open mandate's cumulative budget, minor units; None = default


def _pick(category: str, n: int) -> str:
    return [i.id for i in load_catalog().items if i.category == category][n]


def build_tasks() -> list[Task]:
    """26 autonomous purchases across the five categories plus one human-present purchase.

    Quantities 1 to 2; one or two lines; budgets exactly at the total, one cent above it, and
    generous. The set is fixed by this function (no randomness), so every run buys the same things."""
    catalog = {i.id: i for i in load_catalog().items}
    tasks: list[Task] = []

    def add(
        name: str, text: str, lines: tuple[tuple[str, int], ...], budget: str = "default"
    ) -> None:
        total = sum(catalog[i].price.minor * q for i, q in lines)
        value = {"default": None, "exact": total, "above": total + 1, "ample": total * 5}[budget]
        tasks.append(Task(f"task_{len(tasks) + 1:02d}_{name}", text, "autonomous", lines, value))

    for category in ("headphones", "speakers", "chargers", "cables", "accessories"):
        add(
            f"{category}_single", f"One {category} item, default budget", ((_pick(category, 0), 1),)
        )
        add(f"{category}_pair", f"Two of one {category} item", ((_pick(category, 1), 2),), "ample")
        add(f"{category}_exact_budget", f"One {category} item, budget equals the total",
            ((_pick(category, 2), 1),), "exact")  # fmt: skip
        add(f"{category}_tight_budget", f"One {category} item, budget one cent above the total",
            ((_pick(category, 3), 1),), "above")  # fmt: skip
        add(f"{category}_two_lines", f"Two different {category} items in one checkout",
            ((_pick(category, 4), 1), (_pick(category, 5), 1)), "ample")  # fmt: skip
    add("mixed_basket", "A headphone and its cable in one checkout",
        ((_pick("headphones", 0), 1), (_pick("cables", 0), 1)), "ample")  # fmt: skip
    tasks.append(
        Task(
            f"task_{len(tasks) + 1:02d}_human_present",
            "The customer approves the exact checkout on the Trusted Surface",
            "human_present",
            ((_pick("speakers", 0), 1),),
        )
    )
    return tasks
