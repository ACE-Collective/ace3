"""The yara scanner service: a pre-forked pool of processes that scan files with yara on behalf of
the engine, reached over a local unix socket (docs/YARA_SCANNER.md).

- protocol.py -- the wire format shared by both ends
- match_record.py -- a match as stores keep it (YARA QA, SVS samples), and its summary
- server.py -- the manager, generation and worker processes
- client.py -- what the engine calls
- service.py -- the ACE service wrapper and its configuration
"""
