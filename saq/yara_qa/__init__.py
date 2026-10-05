"""Files matched by YARA rules in QA mode, kept in the CAS for analyst review (docs/YARA_QA.md).

store.record_qa_match is called by the yara scanner service's qa recorder for every QA-mode match;
prune removes expired matches; listing merges the rules currently in QA mode (from the YARA rule
inventory, saq/signatures/yara_inventory.py), including ones that never matched, with what was
recorded, for the API and the CLI. The match record format is saq/yara_scanning/match_record.py.
"""
