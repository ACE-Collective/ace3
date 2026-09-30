"""Files matched by YARA rules in QA mode, kept in the CAS for analyst review (docs/YARA_QA.md).

store.record_qa_match is called by the scanner module for every QA-mode match; prune removes
expired matches; inventory lists the rules currently in QA mode, including ones that never matched;
listing merges the two for the API and the CLI; archive builds the password protected zips the
API serves.
"""
