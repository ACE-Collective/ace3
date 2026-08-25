from datetime import datetime

import pytest

from saq.analysis.root import load_root
from saq.constants import F_MESSAGE_ID
from saq.database import get_db_connection
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.email.conversation import Participant, ThreadContext, record_thread
from saq.modules.email.thread import EmailThreadAnalysis
from saq.util.uuid import get_storage_dir

# a look-a-like of example.com: "rn" reads as "m"
LOOKALIKE_DOMAIN = "exarnple.com"


def _context(thread_id, message_id, participants, message_date, normalized_subject="quarterly review",
             in_reply_to=None):
    senders = [p for p in participants if p.role in ("from", "reply_to", "return_path")]
    from_participant = next((p for p in participants if p.role == "from"), None)
    return ThreadContext(
        thread_id=thread_id,
        # default: no In-Reply-To / References, so each message threads to itself - the conversation
        # is only recoverable through normalized subject plus a shared participant domain. passing
        # in_reply_to (with a shared thread_id) models a header-threaded reply chain instead.
        thread_method="self" if in_reply_to is None else "in_reply_to",
        message_id=message_id,
        in_reply_to=in_reply_to,
        references=None,
        normalized_subject=normalized_subject,
        message_date=message_date,
        from_address=from_participant.address if from_participant else None,
        from_domain=from_participant.domain if from_participant else None,
        direction=0,
        participants=participants,
        senders=senders,
    )


def _strip_message_attribution(thread_id):
    """Blank message_id_hash on a thread's participant rows, reproducing pre-per-message records.

    email_thread_domain.message_id_hash was added to live tables after the recorder had already
    been writing per-thread rows, so production carries rows that cannot be tied to a message.
    Nothing in the code path can produce them any more, which is exactly why they need a fixture.
    """
    with get_db_connection(name="brocess") as db:
        cursor = db.cursor()
        cursor.execute("""
UPDATE email_thread_domain SET message_id_hash = NULL
WHERE thread_id_hash = UNHEX(SHA2(%s, 256))""", (thread_id,))
        db.commit()


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

    # a fully-recorded conversation carries no attribution caveats
    assert entry["first_seen_replies_to_unrecorded"] is False
    assert entry["likely_inherited"] is False
    assert analysis.missing_parent_message_ids == []

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


def _record_conversation_opened_by_the_lookalike():
    """The look-a-like opens the exchange, the real domain replies later, nothing threads by header.

    Reduced from a production alert. The two oldest messages' participant rows predate per-message
    tracking, so nothing attributes them to a message - the state that made the module report
    "Sent mail into this conversation" and "Present on 0 of 5 messages" about the same domain.
    """
    for index, when in enumerate([datetime(2026, 7, 30, 13, 58, 0),
                                  datetime(2026, 7, 30, 14, 24, 0)]):
        thread_id = f"<op-{index}@{LOOKALIKE_DOMAIN}>"
        record_thread(_context(
            thread_id, thread_id,
            [Participant("jane.doe@" + LOOKALIKE_DOMAIN, LOOKALIKE_DOMAIN, "from"),
             Participant("jane.doe@" + LOOKALIKE_DOMAIN, LOOKALIKE_DOMAIN, "return_path"),
             Participant(f"bob{index}@company.com", "company.com", "to")],
            when, normalized_subject="please confirm"))
        _strip_message_attribution(thread_id)

    for index, when in enumerate([datetime(2026, 7, 31, 15, 23, 0),
                                  datetime(2026, 7, 31, 15, 23, 51),
                                  datetime(2026, 7, 31, 15, 42, 0)]):
        thread_id = f"<op-real-{index}@example.com>"
        record_thread(_context(
            thread_id, thread_id,
            [Participant("jane.doe@example.com", "example.com", "from"),
             Participant("jane.doe@example.com", "example.com", "return_path"),
             Participant(f"carol{index}@company.com", "company.com", "to")],
            when, normalized_subject="please confirm"))


@pytest.mark.integration
def test_thread_analysis_counts_messages_the_lookalike_sent(root_analysis):
    """Presence must count the message's own sender, not just the participant rows.

    from_domain is on the message row and stays attributable; participant rows written before
    message_id_hash existed do not. Reading only the latter reported a domain as present on zero
    messages while the timeline rendered it as the sender of two of them.
    """
    _record_conversation_opened_by_the_lookalike()

    analysis, _ = _analyze(root_analysis, "<op-real-2@example.com>")
    entry = analysis.lookalikes[0]

    assert entry["domain"] == LOOKALIKE_DOMAIN
    assert entry["counterpart"] == "example.com"
    assert entry["ever_sent"] is True

    # the two messages it sent, found through from_domain alone
    assert entry["message_count"] == 2
    assert entry["total_messages"] == 5
    assert entry["introduced_on"] == "2026-07-30 13:58:00"
    assert entry["introduced_by_address"] == "jane.doe@" + LOOKALIKE_DOMAIN

    # the timeline agrees with itself: the badge column is set on the rows whose From it highlights
    assert [m["from_is_lookalike"] for m in analysis.messages] == [True, True, False, False, False]
    assert [m["lookalike_domains_present"] for m in analysis.messages] == [
        [LOOKALIKE_DOMAIN], [LOOKALIKE_DOMAIN], [], [], []]


@pytest.mark.integration
def test_thread_analysis_reports_partial_attribution(root_analysis):
    """An unattributable record makes the count a floor, and it has to say so.

    The role verdicts count those records and the per-message count cannot, so an unqualified count
    contradicts the line above it.
    """
    _record_conversation_opened_by_the_lookalike()

    analysis, _ = _analyze(root_analysis, "<op-real-2@example.com>")
    entry = analysis.lookalikes[0]
    assert entry["presence_is_partial"] is True

    content = analysis.summary_details[0].content
    assert "Present on 2 of 5 recorded messages" in content
    assert "That count is a floor" in content
    # the contradiction this replaces
    assert "Present on 0 of 5" not in content
    # and we no longer claim absence from the anchor, which we cannot know in this state
    assert "Not present in the message this alert fired on" not in content


@pytest.mark.integration
def test_thread_analysis_names_the_side_on_fewer_messages(root_analysis):
    """A look-a-like that sent FIRST is still the look-a-like.

    "Whichever side is on fewer messages" outranks arrival order - the same rule the phishfinder
    hunt uses when it re-picks which side to display. Arrival order only means anything in a
    conversation the threading headers grouped; a subject-merged pile of self-threaded messages is
    ordered by nothing but when each independent message landed, so ranking by it named the real
    domain as the imposter whenever the impostor opened the exchange.
    """
    _record_conversation_opened_by_the_lookalike()

    analysis, _ = _analyze(root_analysis, "<op-real-2@example.com>")
    entry = analysis.lookalikes[0]

    # the look-a-like is on messages 1-2, the real domain on 3-5, so it is FIRST in the timeline
    assert analysis.messages[0]["from_domain"] == LOOKALIKE_DOMAIN
    assert entry["domain"] == LOOKALIKE_DOMAIN
    assert entry["counterpart"] == "example.com"
    assert LOOKALIKE_DOMAIN in analysis.summary_details[0].content.split("(looks like")[0]


def _record_one_sided_reply_chain():
    """One side of a header-threaded exchange, with every reply pointing at unrecorded mail.

    Reduced from a production alert. Only inbound mail is recorded (the journal feed drops the
    outbound direction), so the conversation is the external sender's messages only, and each one
    replies to an internal message that is not in the record. The look-a-like address first appears
    in the recipient list of the final reply - put there by the UNRECORDED internal message it
    replies to (an internal typo), not by the external sender, who merely replied-all.
    """
    root = "<gap-root@example.com>"

    record_thread(_context(
        root, "<gap-1@example.com>",
        [Participant("jane.doe@example.com", "example.com", "from"),
         Participant("bob@company.com", "company.com", "to")],
        datetime(2026, 8, 1, 9, 0, 0),
        normalized_subject="service contract for signature",
        in_reply_to=root))

    record_thread(_context(
        root, "<gap-2@example.com>",
        [Participant("jane.doe@example.com", "example.com", "from"),
         Participant("bob@company.com", "company.com", "to")],
        datetime(2026, 8, 10, 9, 0, 0),
        normalized_subject="service contract for signature",
        in_reply_to="<gap-unrecorded-1@company.com>"))

    # the anchor: a reply-all to an unrecorded internal message whose recipient list carried the
    # look-a-like address; the external sender inherits it into To
    record_thread(_context(
        root, "<gap-3@example.com>",
        [Participant("jane.doe@example.com", "example.com", "from"),
         Participant("bob@company.com", "company.com", "to"),
         Participant("tom@" + LOOKALIKE_DOMAIN, LOOKALIKE_DOMAIN, "to")],
        datetime(2026, 8, 21, 9, 0, 0),
        normalized_subject="service contract for signature",
        in_reply_to="<gap-unrecorded-2@company.com>"))


@pytest.mark.integration
def test_thread_analysis_does_not_blame_the_replier_for_an_inherited_address(root_analysis):
    """A first recorded sighting on a reply to unrecorded mail is not an introduction.

    Regression: the module reported the look-a-like address as "introduced by" the external sender
    of the alerting message, when the message it replied to - outbound internal mail the journal
    feed never records - had already carried the address (an internal typo). The analyst read that
    as the external party injecting a look-a-like address and started investigating the wrong side.
    """
    _record_one_sided_reply_chain()

    analysis, _ = _analyze(root_analysis, "<gap-3@example.com>")
    assert analysis is not None
    assert analysis.thread_method == "headers"

    # the record provably has holes, and they are surfaced as lookup keys for enrichment - the
    # thread root itself counts, since the exchange opened with a message that was never recorded
    assert analysis.missing_parent_message_ids == [
        "<gap-root@example.com>", "<gap-unrecorded-1@company.com>", "<gap-unrecorded-2@company.com>"]
    assert [m["replies_to_unrecorded"] for m in analysis.messages] == [True, True, True]

    entry = analysis.lookalikes[0]
    assert entry["domain"] == LOOKALIKE_DOMAIN
    assert entry["counterpart"] == "example.com"

    # first recorded appearance is stated, with both caveats attached
    assert entry["introduced_on"] == "2026-08-21 09:00:00"
    assert entry["introduced_by_address"] == "jane.doe@example.com"
    assert entry["first_seen_replies_to_unrecorded"] is True
    assert entry["likely_inherited"] is True

    content = analysis.summary_details[0].content
    assert "Present on 1 of 3 recorded messages" in content
    assert "first recorded appearance 2026-08-21 09:00:00 on a message from jane.doe@example.com" in content
    # the old wording asserted an introduction the record cannot support
    assert "introduced" not in content
    assert "likely carried over" in content
    assert "never recorded" in content


@pytest.mark.integration
def test_thread_analysis_sender_of_a_gapped_reply_is_not_inherited(root_analysis):
    """A domain that SENT the first message it appears on was not carried over from anyone.

    The inherited caveat is only for recipient-role sightings: when the look-a-like's first recorded
    appearance is a reply it sent itself, uncertainty about earlier presence remains (the parent is
    unrecorded), but "this sender likely did not add the address" would be false - it wrote the
    message. The dangerous shape must not be softened by the benign caveat.
    """
    _record_one_sided_reply_chain()

    # the look-a-like sends into the conversation BEFORE the reply-all that carries it as a
    # recipient, so its first recorded appearance is its own message
    record_thread(_context(
        "<gap-root@example.com>", "<gap-4@" + LOOKALIKE_DOMAIN + ">",
        [Participant("tom@" + LOOKALIKE_DOMAIN, LOOKALIKE_DOMAIN, "from"),
         Participant("bob@company.com", "company.com", "to")],
        datetime(2026, 8, 15, 9, 0, 0),
        normalized_subject="service contract for signature",
        in_reply_to="<gap-unrecorded-3@company.com>"))

    analysis, _ = _analyze(root_analysis, "<gap-4@" + LOOKALIKE_DOMAIN + ">")
    entry = analysis.lookalikes[0]
    assert entry["domain"] == LOOKALIKE_DOMAIN

    assert entry["ever_sent"] is True
    assert entry["introduced_on"] == "2026-08-15 09:00:00"
    assert entry["introduced_by_address"] == "tom@" + LOOKALIKE_DOMAIN
    # the gap is still acknowledged, but the sighting is not called inherited
    assert entry["first_seen_replies_to_unrecorded"] is True
    assert entry["likely_inherited"] is False
    assert "likely carried over" not in analysis.summary_details[0].content


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
