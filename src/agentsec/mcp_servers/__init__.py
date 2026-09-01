"""Real MCP servers, spoken over stdio (AS-015 onward).

These are genuine protocol servers rather than in-process fakes, so the gateway is a real
MCP client. They make no authorization decisions - see ADR-0001 - and enforce containment
only: even a fully compromised gateway must not read outside the fixture corpus.
"""
