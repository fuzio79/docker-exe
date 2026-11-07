"""Test configuration.

`main.py` raises at import time when DOCKER_EXEC_API_KEY is unset (by design --
a missing key must not start a socket-management service). The tests therefore
have to set the variables BEFORE importing it, which is why this lives in
conftest.py and not in a fixture.
"""

import os

# Must be set before `import main`.
os.environ.setdefault("DOCKER_EXEC_API_KEY", "test-api-key-not-a-real-secret")
os.environ.setdefault("EXEC_TIMEOUT_WRAPPER", "1")

# Make sure the test suite can never accidentally talk to a real daemon via a
# leaked DOCKER_HOST in the developer's shell. Tests that need a client inject a
# fake explicitly.
os.environ.pop("DOCKER_HOST", None)
