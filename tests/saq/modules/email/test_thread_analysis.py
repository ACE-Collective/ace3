from datetime import datetime

import pytest

from saq.analysis.root import load_root
from saq.constants import F_MESSAGE_ID
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.email.conversation import Participant, ThreadContext, record_thread
from saq.modules.email.thread import EmailThreadAnalysis
from saq.util.uuid import get_storage_dir

# a look-a-like of example.com: "rn" reads as "m"
LOOKALIKE_DOMAIN = "exarnple.com"


def _context(thread_id, message_id, participants, message_date, normalized_subject="quarterly review"):
    senders = [p for p in participants if p.role in ("from", "reply_to", "return_path")]
    from_participant = next((p for p in participants if p.role == "from"), None)
    return ThreadContext(
        thread_id=thread_id,
        # no In-Reply-To / References, so each message threads to itself - the conversation is only
        # recoverable through normalized subject plus a shared participant domain
        thread_method="self",
        message_id=message_id,
        in_reply_to=None,
        references=None,
        normalized_subject=normalized_subject,
        message_date=message_date,
        from_address=from_participant.address if from_participant else None,
        from_domain=from_participant.domain if from_participant else None,
        direction=0,
        participants=participants,
        senders=senders,
    )


def _record_conversation():
    """Record the shape the phishfinder look-a-like hunt actually alerts on.

    A look-a-like domain is cc'd onto the middle message of a conversation by a third party, is
    never a sender, and is absent from the message the alert eventually fires on.
    """
    record_thread(_context(
        "<t1@example.com>", "<t1@example.com>",
        [Participant("jane.doe@example.com", "example.com", "from"),
         Participant("bob@company.com", "company.com", "to")],
        datetime(2026, 3, 1, 9, 0, 0)))

    record_thread(_context(
        "<t2@company.com>", "<t2@company.com>",
        [Participant("bob@company.com", "company.com", "from"),
         Participant("jane.doe@example.com", "example.com", "to"),
         Participant("jane.doe@" + LOOKALIKE_DOMAIN, LOOKALIKE_DOMAIN, "cc")],
        datetime(2026, 3, 2, 9, 0, 0)))

    record_thread(_context(
        "<t3@example.com>", "<t3@example.com>",
        [Participant("jane.doe@example.com", "example.com", "from"),
         Participant("bob@company.com", "company.com", "to")],
        datetime(2026, 3, 3, 9, 0, 0)))


def _analyze(root_analysis, message_id):
    """Run email_thread_analyzer against a message_id observable and return (analysis, observable)."""
    root_analysis.analysis_mode = "test_groups"
    observable = root_analysis.add_observable_by_spec(F_MESSAGE_ID, message_id)
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    engine.configuration_manager.enable_module("email_thread_analyzer", "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root_analysis = load_root(get_storage_dir(root_analysis.uuid))
    observable = root_analysis.get_observable(observable.uuid)
    return observable.get_and_load_analysis(EmailThreadAnalysis), observable


@pytest.mark.integration
def test_thread_analysis_builds_the_timeline(root_analysis):
    _record_conversation()

    analysis, _ = _analyze(root_analysis, "<t3@example.com>")
    assert analysis is not None

    # all three messages, oldest first, with the alerting message marked
    assert [m["index"] for m in analysis.messages] == [1, 2, 3]
    assert [m["date"] for m in analysis.messages] == [
        "2026-03-01 09:00:00", "2026-03-02 09:00:00", "2026-03-03 09:00:00"]
    assert [m["is_anchor"] for m in analysis.messages] == [False, False, True]
    assert analysis.messages[1]["from_address"] == "bob@company.com"

    # recipients are per-message, so the look-a-like is flagged on message 2 only
    assert [m["lookalike_domains_present"] for m in analysis.messages] == [
        [], [LOOKALIKE_DOMAIN], []]
    # the look-a-like recipient is flagged individually and sorted first, so it cannot hide in a
    # list next to the real address it imitates
    recipients = analysis.messages[1]["recipients"]
    assert recipients[0] == {"address": "jane.doe@" + LOOKALIKE_DOMAIN, "is_lookalike": True}
    assert all(not r["is_lookalike"] for r in recipients[1:])
    assert analysis.messages[1]["from_is_lookalike"] is False


@pytest.mark.integration
def test_thread_analysis_reports_recipient_only_lookalike(root_analysis):
    _record_conversation()

    analysis, _ = _analyze(root_analysis, "<t3@example.com>")
    assert len(analysis.lookalikes) == 1
    entry = analysis.lookalikes[0]

    assert entry["domain"] == LOOKALIKE_DOMAIN
    assert entry["counterpart"] == "example.com"

    # the fact that disposes of the alert: it never sent mail into this conversation
    assert entry["ever_sent"] is False
    assert entry["roles"] == ["cc"]

    # where it came from, and that it is not in the message the alert fired on
    assert entry["message_count"] == 1
    assert entry["total_messages"] == 3
    assert entry["introduced_on"] == "2026-03-02 09:00:00"
    assert entry["introduced_by_address"] == "bob@company.com"
    assert entry["present_in_anchor_message"] is False

    # the look-a-like address clones a real participant's local part verbatim
    assert entry["impersonations"] == [{
        "address": "jane.doe@" + LOOKALIKE_DOMAIN,
        "impersonates": "jane.doe@example.com",
        "exact_local_part": True,
    }]


@pytest.mark.integration
def test_thread_analysis_flags_a_lookalike_that_sent_mail(root_analysis):
    _record_conversation()

    # the dangerous shape: the look-a-like now sends into the conversation
    record_thread(_context(
        "<t4@" + LOOKALIKE_DOMAIN + ">", "<t4@" + LOOKALIKE_DOMAIN + ">",
        [Participant("jane.doe@" + LOOKALIKE_DOMAIN, LOOKALIKE_DOMAIN, "from"),
         Participant("bob@company.com", "company.com", "to")],
        datetime(2026, 3, 4, 9, 0, 0)))

    analysis, _ = _analyze(root_analysis, "<t4@" + LOOKALIKE_DOMAIN + ">")
    entry = analysis.lookalikes[0]
    assert entry["domain"] == LOOKALIKE_DOMAIN
    assert entry["ever_sent"] is True
    assert "from" in entry["roles"]
    assert entry["present_in_anchor_message"] is True
    assert "sent mail into this conversation" in analysis.summary


@pytest.mark.integration
def test_thread_analysis_separates_reply_to_from_sending(root_analysis):
    """A domain that only ever appears as Reply-To has not sent anything.

    Modelled on a real pair: two near-identical domains run by one bulk sender, each sending from
    its own domain but pointing every Reply-To at a single address. Counting reply_to as "sent
    mail" reports the benign operator as an active sender and pushes the analyst to escalate.
    """
    shared_reply_to = "cs@" + LOOKALIKE_DOMAIN

    for index, when in enumerate([datetime(2026, 5, 1, 9, 0, 0), datetime(2026, 5, 2, 9, 0, 0)]):
        participants = [
            Participant("news@example.com", "example.com", "from"),
            Participant("news@example.com", "example.com", "return_path"),
            # replies to both blasts are funnelled to the look-a-like domain
            Participant(shared_reply_to, LOOKALIKE_DOMAIN, "reply_to"),
            Participant("bob@company.com", "company.com", "to"),
        ]
        context = _context(f"<rt-{index}@example.com>", f"<rt-{index}@example.com>",
                           participants, when, normalized_subject="webinar invitation")
        context.senders = [p for p in participants if p.role in ("from", "reply_to", "return_path")]
        record_thread(context)

    analysis, _ = _analyze(root_analysis, "<rt-1@example.com>")
    entry = analysis.lookalikes[0]

    assert entry["domain"] == LOOKALIKE_DOMAIN
    assert entry["roles"] == ["reply_to"]
    # the point of the test: Reply-To is not sending
    assert entry["ever_sent"] is False
    assert entry["ever_reply_to"] is True
    # both messages were sent from example.com, so this is NOT yet the both-sides pattern
    assert entry["reply_to_addresses"] == [shared_reply_to]
    assert entry["shared_reply_to"] == []

    content = analysis.summary_details[0].content
    assert "never sent mail into this conversation, but replies were directed to it" in content.lower()
    assert shared_reply_to in content
    # a one-sided reply-to is a redirect, not shared operation - it must not be described as the
    # latter, or the display argues for exoneration on the suspicious case
    assert "from one side of the pair only" in content
    assert "both" not in content.split("Replies are directed")[1].split("\n")[0].lower()

    # and it has to be visible in the timeline, not just the findings - Reply-To is a sender role, so
    # it appears in neither the From address nor the recipient list
    assert analysis.messages[0]["other_senders"] == [
        {"address": shared_reply_to, "role": "reply_to", "is_lookalike": True}]


@pytest.mark.integration
def test_thread_analysis_shared_reply_to_needs_both_sides(root_analysis):
    """Only call it shared operation when messages from BOTH domains point at the same address."""
    shared = "cs@" + LOOKALIKE_DOMAIN

    for index, (sender, domain) in enumerate([("news@example.com", "example.com"),
                                              ("news@" + LOOKALIKE_DOMAIN, LOOKALIKE_DOMAIN)]):
        participants = [
            Participant(sender, domain, "from"),
            Participant(sender, domain, "return_path"),
            Participant(shared, LOOKALIKE_DOMAIN, "reply_to"),
            Participant("bob@company.com", "company.com", "to"),
        ]
        context = _context(f"<sh-{index}@{domain}>", f"<sh-{index}@{domain}>", participants,
                           datetime(2026, 6, 1 + index, 9, 0, 0),
                           normalized_subject="quarterly newsletter")
        context.senders = [p for p in participants if p.role in ("from", "reply_to", "return_path")]
        record_thread(context)

    analysis, _ = _analyze(root_analysis, f"<sh-1@{LOOKALIKE_DOMAIN}>")
    entry = analysis.lookalikes[0]

    # each domain sent one of the two messages and both carried the same Reply-To
    assert entry["shared_reply_to"] == [shared]
    assert "both" in analysis.summary_details[0].content.lower()


@pytest.mark.integration
def test_thread_analysis_names_the_newcomer_as_the_lookalike(root_analysis):
    """When both sides send, the domain that arrived later is the look-a-like.

    Regression: with a Cyrillic homoglyph the tiebreak fell through to alphabetical order, which
    sorts U+0430 after ASCII, so the module labelled the REAL domain as the imposter.
    """
    cyrillic = "exаmple.com"
    for index, (sender, domain) in enumerate([
            ("finance@example.com", "example.com"),      # established first
            ("ap@company.com", "company.com"),
            (f"finance@{cyrillic}", cyrillic)]):         # the newcomer
        participants = [Participant(sender, domain, "from"),
                        Participant(sender, domain, "return_path"),
                        Participant("ap@company.com", "company.com", "to")]
        record_thread(_context(f"<cy-{index}@{domain}>", f"<cy-{index}@{domain}>", participants,
                               datetime(2026, 8, 1 + index, 9, 0, 0),
                               normalized_subject="vendor onboarding"))

    analysis, _ = _analyze(root_analysis, f"<cy-2@{cyrillic}>")
    entry = next(e for e in analysis.lookalikes if cyrillic in (e["domain"], e["counterpart"]))
    assert entry["domain"] == cyrillic
    assert entry["counterpart"] == "example.com"


@pytest.mark.integration
def test_thread_analysis_is_display_only(root_analysis):
    _record_conversation()

    analysis, observable = _analyze(root_analysis, "<t3@example.com>")

    # this module explains an existing alert - it must not be able to create or change one
    assert analysis.detections == []
    assert observable.detections == []
    assert observable.tags == []
    assert analysis.observables == []

    # the decisive findings are published inline so they show in the tree without a drill-down
    assert len(analysis.summary_details) == 1
    content = analysis.summary_details[0].content
    assert "Never sent mail into this conversation" in content
    assert "Not present in the message this alert fired on" in content


@pytest.mark.integration
def test_thread_analysis_skips_unrecorded_message(root_analysis):
    # thread recording disabled, or a message older than the thread store - no analysis, no error.
    # the module ran and declined, which ACE records as False rather than None
    analysis, _ = _analyze(root_analysis, "<never-recorded@example.com>")
    assert not analysis


@pytest.mark.integration
def test_thread_analysis_without_lookalikes(root_analysis):
    record_thread(_context(
        "<clean1@example.com>", "<clean1@example.com>",
        [Participant("jane.doe@example.com", "example.com", "from"),
         Participant("bob@company.com", "company.com", "to")],
        datetime(2026, 3, 1, 9, 0, 0),
        normalized_subject="lunch plans"))

    analysis, _ = _analyze(root_analysis, "<clean1@example.com>")
    assert analysis is not None
    assert analysis.lookalikes == []
    assert len(analysis.messages) == 1
    # nothing decisive to say, so nothing is pushed inline into the tree
    assert analysis.summary_details == []
