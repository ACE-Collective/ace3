
from datetime import datetime
import os
import pytest

from saq.analysis.root import RootAnalysis, Submission
from saq.configuration.config import get_config
from saq.constants import CONFIG_COLLECTION_TUNING_UPDATE_FREQUENCY, F_IP
from saq.submission_filter import TUNING_TARGET_ALL, TUNING_TARGET_FILES, TUNING_TARGET_SUBMISSION, SubmissionFilter

from yara_scanner import YaraScanner

from saq.util.time import local_time

@pytest.fixture
def mock_tuning_rules(monkeypatch, tmpdir):
    tuning_rules_dir = tmpdir / "tuning_rules_dir"
    tuning_rules_dir.mkdir()

    monkeypatch.setattr(get_config().collection, "tuning_dirs", [str(tuning_rules_dir)])
    return tuning_rules_dir

def create_submission_filter():
    filter = SubmissionFilter()
    filter.load_tuning_rules()
    return filter

@pytest.fixture
def submission(tmpdir):
    root = RootAnalysis(
        storage_dir = str(tmpdir / "submission_root"),
        desc='test_description',
        analysis_mode='analysis',
        tool='unittest_tool',
        tool_instance='unittest_tool_instance',
        alert_type='unittest_type',
        event_time=datetime.now(),
        details={'hello': 'world'})
    root.initialize_storage()
    return Submission(root)

@pytest.mark.unit
def test_tuning_rule_reload(mock_tuning_rules, monkeypatch):
    monkeypatch.setattr(get_config().collection, CONFIG_COLLECTION_TUNING_UPDATE_FREQUENCY, "00:00:00")
    with open(os.path.join(mock_tuning_rules, 'test.yar'), 'w') as fp:
        fp.write("""
rule test_submission {
    meta:
        targets = "submission"
    strings:
        $ = "test"
    condition:
        all of them
}
""")
    submission_filter = create_submission_filter()

    existing_tuning_scanners = submission_filter.tuning_scanners

    with open(os.path.join(mock_tuning_rules, 'test.yar'), 'w') as fp:
        fp.write("""
rule test_submission {
    meta:
        targets = "submission"
    strings:
        $ = "test"
        $ = "new string"
    condition:
        all of them
}
""")
    submission_filter.update_rules()
    assert submission_filter.tuning_scanners != existing_tuning_scanners

@pytest.mark.unit
def test_tuning_rule_no_reload(mock_tuning_rules, monkeypatch):
    monkeypatch.setattr(get_config().collection, CONFIG_COLLECTION_TUNING_UPDATE_FREQUENCY, "01:00:00")
    with open(os.path.join(mock_tuning_rules, 'test.yar'), 'w') as fp:
        fp.write("""
rule test_submission {
    meta:
        targets = "submission"
    strings:
        $ = "test"
    condition:
        all of them
}
""")
    submission_filter = create_submission_filter()
    existing_tuning_scanners = submission_filter.tuning_scanners
    submission_filter.update_rules()
    assert existing_tuning_scanners == submission_filter.tuning_scanners

@pytest.mark.unit
def test_tuning_rules_load_single_target(mock_tuning_rules):
    with open(os.path.join(mock_tuning_rules, 'test.yar'), 'w') as fp:
        fp.write("""
rule test_submission {
    meta:
        targets = "submission"
    strings:
        $ = "test"
    condition:
        all of them
}
""")
    submission_filter = create_submission_filter()
    
    assert TUNING_TARGET_SUBMISSION in submission_filter.tuning_scanners
    assert TUNING_TARGET_FILES not in submission_filter.tuning_scanners
    assert TUNING_TARGET_ALL not in submission_filter.tuning_scanners
    assert isinstance(submission_filter.tuning_scanners[TUNING_TARGET_SUBMISSION], YaraScanner)


@pytest.mark.unit
def test_tuning_rules_load_multi_target(mock_tuning_rules):
    with open(os.path.join(mock_tuning_rules, 'test.yar'), 'w') as fp:
        fp.write("""
rule test_submission {
    meta:
        targets = "submission,files,all"
    strings:
        $ = "test"
    condition:
        all of them
}
""")
    submission_filter = create_submission_filter()
    
    assert TUNING_TARGET_SUBMISSION in submission_filter.tuning_scanners
    assert TUNING_TARGET_FILES in submission_filter.tuning_scanners
    assert TUNING_TARGET_ALL in submission_filter.tuning_scanners
    assert isinstance(submission_filter.tuning_scanners[TUNING_TARGET_SUBMISSION], YaraScanner)

@pytest.mark.unit
def test_tuning_rules_load_multi_rules(mock_tuning_rules):
    with open(os.path.join(mock_tuning_rules, 'test.yar'), 'w') as fp:
        fp.write("""
rule test_submission {
    meta:
        targets = "submission"
    strings:
        $ = "test"
    condition:
        all of them
}
rule test_files {
    meta:
        targets = "files"
    strings:
        $ = "test"
    condition:
        all of them
}
rule test_all {
    meta:
        targets = "all"
    strings:
        $ = "test"
    condition:
        all of them
}
""")
    submission_filter = create_submission_filter()
    
    assert TUNING_TARGET_SUBMISSION in submission_filter.tuning_scanners
    assert TUNING_TARGET_FILES in submission_filter.tuning_scanners
    assert TUNING_TARGET_ALL in submission_filter.tuning_scanners
    assert isinstance(submission_filter.tuning_scanners[TUNING_TARGET_SUBMISSION], YaraScanner)

@pytest.mark.unit
def test_tuning_rules_load_missing_target(mock_tuning_rules):
    with open(os.path.join(mock_tuning_rules, 'test.yar'), 'w') as fp:
        fp.write("""
rule test_submission {
    strings:
        $ = "test"
    condition:
        all of them
}
""")
    submission_filter = create_submission_filter()
    
    # no scanners should be loaded at all
    assert not submission_filter.tuning_scanners

@pytest.mark.unit
def test_tuning_rules_load_invalid_target(mock_tuning_rules):
    with open(os.path.join(mock_tuning_rules, 'test.yar'), 'w') as fp:
        fp.write("""
rule test_submission {
    meta:
        targets = "invalid"
    strings:
        $ = "test"
    condition:
        all of them
}
""")
    submission_filter = create_submission_filter()
    
    # no scanners should be loaded at all
    assert not submission_filter.tuning_scanners

@pytest.mark.unit
def test_tuning_rules_load_syntax_error(mock_tuning_rules):
    with open(os.path.join(mock_tuning_rules, 'test.yar'), 'w') as fp:
        fp.write("""
rule test_submission {
    meta:
        targets = "submission"
    strings:
        $ = "test"
    condition:
        all of them
""")
    submission_filter = create_submission_filter()
    
    assert not submission_filter.tuning_scanners

@pytest.mark.unit
def test_tuning_rules_submission_match(mock_tuning_rules, submission):
    with open(os.path.join(mock_tuning_rules, 'test.yar'), 'w') as fp:
        fp.write("""
rule test_submission {
    meta:
        targets = "submission"
    strings:
        $ = "test_description"
    condition:
        all of them
}
""")
    submission_filter = create_submission_filter()

    matches = submission_filter.get_tuning_matches(submission)
    submission_filter.log_tuning_matches(submission, matches)
    assert matches
    assert matches[0]['rule'] == 'test_submission'

@pytest.mark.unit
def test_tuning_rules_observable_match(mock_tuning_rules, submission):

# sample observable layout
#  {
#   "time": "2020-02-14T20:45:00.620518+0000",
#   "type": "ip",
#   "value": "1.2.3.4"
#  },

    with open(os.path.join(mock_tuning_rules, 'test.yar'), 'w') as fp:
        fp.write("""
rule test_observable {
    meta:
        targets = "observable"
    strings:
        $ = /"type": "ip"/
        $ = /"value": "1.2.3.4"/
    condition:
        all of them
}
""")
    submission_filter = create_submission_filter()
    submission.root.add_observable_by_spec(F_IP, "1.2.3.4", local_time())
    matches = submission_filter.get_tuning_matches(submission)
    submission_filter.log_tuning_matches(submission, matches)
    assert matches
    assert matches[0]['rule'] == 'test_observable'

@pytest.mark.unit
def test_tuning_rules_submission_all_fields_match(mock_tuning_rules, submission):

# sample observable layout
#   [
#    {
#     "time": "2020-02-14T20:45:00.620518+0000",
#     "type": "ip",
#     "value": "1.2.3.4"
#    },
#    {
#     "time": "2020-02-14T20:45:00.620565+0000",
#     "type": "ip",
#     "value": "1.2.3.5"
#    }
#   ]

    # same as above but testing multiple rule matches
    with open(os.path.join(mock_tuning_rules, 'test.yar'), 'w') as fp:
        fp.write("""
rule test_description {
    meta:
        targets = "submission"
    strings:
        $ = "description = test_description"
    condition:
        all of them
}

rule test_analysis_mode {
    meta:
        targets = "submission"
    strings:
        $ = "analysis_mode = analysis"
    condition:
        all of them
}

rule test_tool {
    meta:
        targets = "submission"
    strings:
        $ = "tool = unittest_tool"
    condition:
        all of them
}

rule test_tool_instance {
    meta:
        targets = "submission"
    strings:
        $ = "tool_instance = unittest_tool_instance"
    condition:
        all of them
}

rule test_type {
    meta:
        targets = "submission"
    strings:
        $ = "type = unittest_type"
    condition:
        all of them
}

rule test_event_time {
    meta:
        targets = "submission"
    strings:
        $ = /\\nevent_time =/
    condition:
        all of them
}

rule test_tags {
    meta:
        targets = "submission"
    strings:
        $ = /\\ntags = .*tag_1.*\\n/
    condition:
        all of them
}

rule test_observable {
    meta:
        targets = "observable"
    strings:
        $ = /"type": "ip"/
        $ = /"value": "1.2.3.5"/
    condition:
        all of them
}
""")
    submission_filter = create_submission_filter()
    for tag in [ 'tag_1', 'tag_2' ]:
        submission.root.add_tag(tag)

    submission.root.add_observable_by_spec(F_IP, "1.2.3.4", local_time())
    submission.root.add_observable_by_spec(F_IP, "1.2.3.5", local_time())
    matches = submission_filter.get_tuning_matches(submission)
    submission_filter.log_tuning_matches(submission, matches)
    # looks like there's a bug in the library that is returning multiple match results for the same match
    #self.assertTrue(len(matches) == 7)
    rule_names = [_['rule'] for _ in matches]
    for rule_name in [
        'test_description',
        'test_analysis_mode',   
        'test_tool',
        'test_tool_instance',
        'test_type',
        'test_event_time',
        'test_tags',
        'test_observable', ]:
        assert rule_name in rule_names

@pytest.mark.unit
def test_tuning_rules_files_match(mock_tuning_rules, tmpdir, submission):
    with open(os.path.join(mock_tuning_rules, 'test.yar'), 'w') as fp:
        fp.write("""
rule test_files {
    meta:
        targets = "files"
    strings:
        $ = "Hello, world!"
    condition:
        all of them
}
""")

    submission_filter = create_submission_filter()
    test_1 = tmpdir / "test_1.txt"
    test_1.write_text("Hello, world!", encoding="utf8")
    submission.root.add_file_observable(test_1)
    test_2 = tmpdir / "test_2.txt"
    test_2.write_text("Smello, forld!", encoding="utf8")
    submission.root.add_file_observable(test_2)
    matches = submission_filter.get_tuning_matches(submission)
    submission_filter.log_tuning_matches(submission, matches)
    assert len(matches) == 1
    assert matches[0]['rule'] == 'test_files'

@pytest.mark.unit
def test_tuning_rules_all_match(mock_tuning_rules, tmpdir, submission):
    with open(os.path.join(mock_tuning_rules, 'test.yar'), 'w') as fp:
        fp.write("""
rule test_all {
    meta:
        targets = "all"
    strings:
        // this is in the submission JSON
        $ = /description = test_description/
        // and this is in the file contents
        $ = "Hello, world!"
        $ = "Smello"
    condition:
        all of them
}
""")

    submission_filter = create_submission_filter()
    test_1 = tmpdir / "test_1.txt"
    test_1.write_text("Hello, world!", encoding="utf8")
    submission.root.add_file_observable(test_1)
    test_2 = tmpdir / "test_2.txt"
    test_2.write_text("Smello, forld!", encoding="utf8")
    submission.root.add_file_observable(test_2)
    matches = submission_filter.get_tuning_matches(submission)
    submission_filter.log_tuning_matches(submission, matches)
    assert len(matches) == 1
    assert matches[0]['rule'] == 'test_all'

@pytest.mark.unit
def test_tuning_rules_observable_match_reported_once(mock_tuning_rules, submission):
    """an observable-target rule is reported once per submission, not once per observable

    the entire observable list is scanned as a single buffer, so a rule that matches
    anywhere in it matches exactly once no matter how many observables are present"""
    with open(os.path.join(mock_tuning_rules, 'test.yar'), 'w') as fp:
        fp.write("""
rule test_observable {
    meta:
        targets = "observable"
    strings:
        $ = /"type": "ip"/
    condition:
        all of them
}
""")
    submission_filter = create_submission_filter()
    for octet in range(1, 11):
        submission.root.add_observable_by_spec(F_IP, f"1.2.3.{octet}", local_time())

    matches = submission_filter.get_tuning_matches(submission)
    assert len([_ for _ in matches if _['rule'] == 'test_observable']) == 1

@pytest.mark.unit
def test_tuning_rules_observable_no_observables(mock_tuning_rules, submission):
    """a submission with no observables produces no observable-target matches"""
    with open(os.path.join(mock_tuning_rules, 'test.yar'), 'w') as fp:
        fp.write("""
rule test_observable {
    meta:
        targets = "observable"
    strings:
        $ = /"type"/
    condition:
        all of them
}
""")
    submission_filter = create_submission_filter()
    assert submission_filter.get_tuning_matches_observable(submission) == []
