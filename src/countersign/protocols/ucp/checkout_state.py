"""Compatibility alias: this module moved to `countersign.checkout.state` so that both protocol adapters share it."""

import sys

from countersign.checkout import state as _moved

sys.modules[__name__] = _moved
