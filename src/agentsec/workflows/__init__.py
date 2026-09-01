"""Durable workflows (S2).

Temporal owns execution state; PostgreSQL owns the product and audit view. Neither is
derived from the other. Workflow code performs no I/O - see security_review.py.
"""
