# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Explicit fixed first-setup recovery; no MCP operation or fallback path."""
from . import authority_setup

def main(runtime_root):
    return authority_setup.main(runtime_root,recover=True)
