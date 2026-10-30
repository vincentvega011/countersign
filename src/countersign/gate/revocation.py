"""Revoking an open mandate. The Trusted Surface calls this in P3; the gate reads it at G-MANDATE."""

from countersign.gate.store import revoke_mandate

__all__ = ["revoke_mandate"]
