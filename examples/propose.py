# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Stellaria-Commercial-1.0
"""Create a synthetic proposal only. No grant, credential or external IO."""
import json
from axr.aet import Action, Resource

action = Action("agent:example", Resource("example", "synthetic", "inbox"),
                "messages.read", "summarize-authorized-input", {"limit": 3})
print(json.dumps({"intent_seal": action.seal, "operation": action.operation,
                  "authorized": False, "executed": False}, indent=2))
