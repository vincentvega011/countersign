"""Shared pytest config.

Hypothesis profiles: `ci` runs 500 examples per property (the default here), `eval` runs 5000.
Select with HYPOTHESIS_PROFILE=eval.
"""

import os

from hypothesis import HealthCheck, settings

settings.register_profile("ci", max_examples=500, suppress_health_check=[HealthCheck.too_slow])
settings.register_profile("eval", max_examples=5000, suppress_health_check=[HealthCheck.too_slow])
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))
