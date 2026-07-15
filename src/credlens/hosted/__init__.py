"""Hosted scan-by-URL surface (docs/specs/hosted-scan.md).

Everything that touches hostile GitHub-tarball bytes lives here, structurally
separate from the network-free shared scanner (credlens.scan). This package is
imported only by the Vercel handler (api/scan.py) and its tests.
"""
