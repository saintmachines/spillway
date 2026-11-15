"""Explicit RC4 control for historical rule-unit tests.

New final014 default tests use Guard directly. These older cases isolate their
named rule, including name-only delegation that the final domain gate refuses.
"""
from spillway_guard import Guard, Policy


def control_guard(*args, **kwargs):
    kwargs.setdefault('policy', Policy())
    return Guard(*args, **kwargs)
