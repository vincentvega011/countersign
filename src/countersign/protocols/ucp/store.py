"""Compatibility alias: this module moved to `countersign.checkout.store` so that both protocol adapters share it."""

import sys

from countersign.checkout import store as _moved

sys.modules[__name__] = _moved
