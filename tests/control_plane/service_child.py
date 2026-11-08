"""Harness process for the P6b subprocess test (not a test module).

``python service_child.py <repo_root> <socket_path>`` builds the demo control
plane through the facade, starts a :class:`ControlPlaneService` that maps the
current uid to AGENT only, prints one JSON ready line (socket path and an
agent credential for the client process) and serves until stdin closes.
"""

from __future__ import annotations

import json
import os
import sys
import threading

from acgs_lite.control_plane import ControlPlaneService, PrincipalKind
from acgs_lite.control_plane.demo_loop import AGENT, REQUESTER, TRIGGER_ID, build_demo_environment


def main(repo_root: str, socket_path: str) -> int:
    env = build_demo_environment(repo_root)
    cp = env.cp
    credential = cp.credentials.issue(
        AGENT,
        scopes=["tool:read_file", "tool:write_file"],
        on_behalf_of=REQUESTER.id,
        trigger_id=TRIGGER_ID,
    )
    service = ControlPlaneService(cp, socket_path, {os.getuid(): frozenset({PrincipalKind.AGENT})})
    with service:
        server = threading.Thread(target=service.serve_forever, daemon=True)
        server.start()
        ready = {
            "socket": str(service.socket_path),
            "credential": credential.token,
            "credential_id": credential.credential_id,
        }
        print(json.dumps(ready), flush=True)
        sys.stdin.read()  # the parent closes stdin to stop the harness
    server.join(timeout=5)
    env.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
