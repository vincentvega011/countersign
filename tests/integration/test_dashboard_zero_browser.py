"""Browser test: a dashboard over an empty database shows 0 on every KPI tile, not blank (L61).

The headline claim "unauthorized captures: 0" must read 0 when there are no rows at all. The tile
value is computed from the data by the Countersign total widget; nothing is hardcoded.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import Engine

from countersign.runtime import Mode, RuntimeSettings
from tests.integration.test_dashboard_detail_browser import _run, _scalar, _start
from tests.mode_support import make_world, reset


@pytest.fixture
def empty(app_engine: Engine, admin_engine: Engine) -> Iterator[tuple[str, dict[str, Any]]]:
    reset(admin_engine)
    assert _scalar(admin_engine, "SELECT count(*) FROM checkout_sessions") == 0
    world = make_world(app_engine, RuntimeSettings(Mode.FULL, "demo"))
    base, server, thread, sock = _start(world.client.app)
    try:
        yield base, {}
    finally:
        server.should_exit = True
        thread.join(10)
        sock.close()


def test_tiles_over_no_rows_read_zero(empty: tuple[str, dict[str, Any]]) -> None:
    base, expected = empty
    _run(base, expected, ["test/zero.test.mjs"])
