"""Structured audit lines for admin actions.

One JSON object per line on stderr, which ECS ships to /ecs/sarcastifyer.
Never pass tokens, codes or passwords in here.
"""

import json
import sys
import time
from datetime import datetime, timezone


def _stderr(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


class AuditLog:
    def __init__(self, write=_stderr, clock=time.time):
        self._write = write
        self._clock = clock

    def admin_action(
        self,
        *,
        action: str,
        admin,
        result: str,
        target_sub: str | None = None,
        target_email: str | None = None,
        previous_email: str | None = None,
    ) -> None:
        """result is "ok" or the name of the error class."""
        record = {
            "event": "admin_action",
            "action": action,
            "admin_sub": admin.sub,
            "admin_email": admin.email,
            "target_sub": target_sub,
            "target_email": target_email,
            "result": result,
            "timestamp": datetime.fromtimestamp(self._clock(), tz=timezone.utc).isoformat(),
        }
        if previous_email is not None:
            record["previous_email"] = previous_email
        self._write(json.dumps(record, sort_keys=True))
