"""The tool runner service: runs the sandboxed tools of every ACE process on a node, each in a cgroup of
its own, so a tool's memory limit counts the memory it uses (docs/TOOL_SANDBOX.md).

- protocol.py -- the request and response both ends share
- cgroup.py -- the per-run cgroups
- server.py -- the server
- client.py -- what run_sandboxed_tool() and correlate executable commands call
- service.py -- the ACE service wrapper and its configuration
"""
