"""Honeypot Hunter — passive, Shodan-only hunting for honeypot/sensor fleets.

Nothing in this package ever opens a connection to a candidate host. Every
signal comes from Shodan's already-collected scan data via api.shodan.io.
"""

__version__ = "2.0.0"
