"""Evaluates user-authored rule expressions."""


def apply_rule(expression: str, context: dict):
    # Arbitrary code execution wherever the expression can be influenced.
    return eval(expression)
