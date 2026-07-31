from datetime import datetime, timedelta

import pytest

from saq.database import get_db_connection
from saq.modules.email.conversation import (
    Participant,
    ThreadContext,
    derive_thread_id,
    get_conversation,
    get_established_domains,
    get_thread_message_count,
    normalize_subject,
    parse_message_id_list,
    record_thread,
)


def _context(thread_id, method, message_id, normalized_subject, participants, **kwargs):
    senders = [p for p in participants if p.role in ("from", "reply_to", "return_path")]
    from_participant = next((p for p in participants if p.role == "from"), None)
    return ThreadContext(
        thread_id=thread_id,
        thread_method=method,
        message_id=message_id,
        in_reply_to=kwargs.get("in_reply_to"),
        references=kwargs.get("references"),
        normalized_subject=normalized_subject,
        message_date=kwargs.get("message_date"),
        from_address=from_participant.address if from_participant else None,
        from_domain=from_participant.domain if from_participant else None,
        direction=0,
        participants=participants,
        senders=senders,
    )


@pytest.mark.unit
@pytest.mark.parametrize("subject,expected", [
    ("Re: Hello", "hello"),
    ("RE: FW: Re: Hello World", "hello world"),
    ("Fwd: project update", "project update"),
    ("Re[2]: counter", "counter"),
    ("   spaced    out   subject ", "spaced out subject"),
    ("no prefix here", "no prefix here"),
    ("", ""),
    (None, ""),
])
def test_normalize_subject(subject, expected):
    assert normalize_subject(subject) == expected


@pytest.mark.unit
def test_parse_message_id_list():
    assert parse_message_id_list("<a@x> <b@x> <c@x>") == ["<a@x>", "<b@x>", "<c@x>"]
    # commas / whitespace between tokens are tolerated
    assert parse_message_id_list("<a@x>,\n <b@x>") == ["<a@x>", "<b@x>"]
    assert parse_message_id_list("") == []
    assert parse_message_id_list(None) == []


@pytest.mark.unit
def test_derive_thread_id_uses_references_root():
    # References is oldest-first; the first token is the JWZ root
    thread_id, method = derive_thread_id("<c@x>", "<b@x>", "<a@x> <b@x>")
    assert thread_id == "<a@x>"
    assert method == "references"


@pytest.mark.unit
def test_derive_thread_id_falls_back_to_in_reply_to():
    thread_id, method = derive_thread_id("<c@x>", "<b@x>", None)
    assert thread_id == "<b@x>"
    assert method == "in_reply_to"


@pytest.mark.unit
def test_derive_thread_id_self_when_no_linkage():
    thread_id, method = derive_thread_id("<c@x>", None, None)
    assert thread_id == "<c@x>"
    assert method == "self"


@pytest.mark.unit
def test_derive_thread_id_normalizes_bare_message_id():
    # a message-id missing angle brackets is normalized when it becomes the thread root
    thread_id, method = derive_thread_id("c@x", None, None)
    assert thread_id == "<c@x>"
    assert method == "self"


@pytest.mark.unit
def test_derive_thread_id_none_when_nothing_available():
    thread_id, method = derive_thread_id(None, None, None)
    assert thread_id == ""
    assert method == "none"


@pytest.mark.unit
def test_derive_thread_id_replies_converge_on_same_root():
    # two different replies in the same thread must map to the same thread_id regardless of arrival order
    a, _ = derive_thread_id("<b@x>", "<a@x>", "<a@x>")
    b, _ = derive_thread_id("<c@x>", "<b@x>", "<a@x> <b@x>")
    assert a == b == "<a@x>"


@pytest.mark.integration
def test_thread_store_round_trip():
    root = _context(
        "<root@example.com>", "self", "<root@example.com>", "invoice question",
        [Participant("ceo@example.com", "example.com", "from"),
         Participant("cfo@company.com", "company.com", "to")])
    record_thread(root)
    assert get_thread_message_count("<root@example.com>") == 1

    # a reply (References the root) sees the root's participant domains as established
    reply = _context(
        "<root@example.com>", "references", "<reply@examp1e.com>", "invoice question",
        [Participant("ceo@examp1e.com", "examp1e.com", "from")],
        in_reply_to="<root@example.com>", references="<root@example.com>")
    established = {d.domain for d in get_established_domains(reply)}
    assert "example.com" in established
    assert "company.com" in established
    # the reply's own look-a-like domain is not yet recorded (recording happens after scoring)
    assert "examp1e.com" not in established


@pytest.mark.integration
def test_subject_fallback_requires_shared_domain():
    root = _context(
        "<root2@example.com>", "self", "<root2@example.com>", "wire transfer",
        [Participant("ceo@example.com", "example.com", "from"),
         Participant("cfo@company.com", "company.com", "to")])
    record_thread(root)

    # no threading headers (method 'self'), same subject, shares company.com -> root domains established
    shared = _context(
        "<isolated@evil.com>", "self", "<isolated@evil.com>", "wire transfer",
        [Participant("cfo@company.com", "company.com", "from")])
    assert "example.com" in {d.domain for d in get_established_domains(shared)}

    # same subject but no shared participant domain -> not merged, nothing established
    unrelated = _context(
        "<other@unrelated.org>", "self", "<other@unrelated.org>", "wire transfer",
        [Participant("bob@unrelated.org", "unrelated.org", "from")])
    assert get_established_domains(unrelated) == []


@pytest.mark.integration
def test_established_domains_collapse_per_message_rows():
    # a participant present on several messages of one thread is recorded once per message, but the
    # established-domain set that look-a-like scoring compares against must hold one entry per
    # (domain, address, role) - otherwise every reference is scored once per message it appeared on
    for index in (1, 2, 3):
        record_thread(_context(
            "<collapse@example.com>", "references", f"<collapse-{index}@example.com>", "status report",
            [Participant("ceo@example.com", "example.com", "from"),
             Participant("cfo@company.com", "company.com", "to")],
            references="<collapse@example.com>"))

    reply = _context(
        "<collapse@example.com>", "references", "<collapse-reply@examp1e.com>", "status report",
        [Participant("ceo@examp1e.com", "examp1e.com", "from")],
        references="<collapse@example.com>")

    established = get_established_domains(reply)
    assert sorted((d.domain, d.address, d.role) for d in established) == [
        ("company.com", "cfo@company.com", "to"),
        ("example.com", "ceo@example.com", "from"),
    ]


def _strip_message_attribution(thread_id):
    """Blank message_id_hash on a thread's participant rows, reproducing pre-per-message records.

    email_thread_domain.message_id_hash was added to live tables after the recorder had already been
    writing per-thread rows, so production carries rows that cannot be tied to a message. Nothing
    in the code path can produce them any more, which is exactly why they need a fixture.
    """
    with get_db_connection(name="brocess") as db:
        cursor = db.cursor()
        cursor.execute("""
UPDATE email_thread_domain SET message_id_hash = NULL
WHERE thread_id_hash = UNHEX(SHA2(%s, 256))""", (thread_id,))
        db.commit()


def _record_conversation():
    """Record a three-message conversation with no threading headers (each message threads to itself).

    a look-a-like of example.com is cc'd on the second message only, and is never a sender.
    """
    record_thread(_context(
        "<c1@example.com>", "self", "<c1@example.com>", "quarterly review",
        [Participant("jane.doe@example.com", "example.com", "from"),
         Participant("bob@company.com", "company.com", "to")],
        message_date=datetime(2026, 3, 1, 9, 0, 0)))

    record_thread(_context(
        "<c2@company.com>", "self", "<c2@company.com>", "quarterly review",
        [Participant("bob@company.com", "company.com", "from"),
         Participant("jane.doe@example.com", "example.com", "to"),
         Participant("jane.doe@exarnple.com", "exarnple.com", "cc")],
        message_date=datetime(2026, 3, 2, 9, 0, 0)))

    record_thread(_context(
        "<c3@example.com>", "self", "<c3@example.com>", "quarterly review",
        [Participant("jane.doe@example.com", "example.com", "from"),
         Participant("bob@company.com", "company.com", "to")],
        message_date=datetime(2026, 3, 3, 9, 0, 0)))


@pytest.mark.integration
def test_get_conversation_spans_subject_linked_threads():
    _record_conversation()

    # every message threads to ITSELF (no In-Reply-To/References), so the three live under three
    # different thread ids. the conversation is only recoverable through normalized subject plus a
    # shared participant domain - the same rule get_established_domains uses.
    conversation = get_conversation("<c3@example.com>")
    assert conversation is not None
    assert conversation.thread_count == 3
    assert [m.message_id for m in conversation.messages] == [
        "<c1@example.com>", "<c2@company.com>", "<c3@example.com>"]
    assert conversation.truncated is False


@pytest.mark.integration
def test_get_conversation_participants_are_per_message():
    _record_conversation()

    conversation = get_conversation("<c3@example.com>")
    by_message = {m.message_id: {p.address for p in conversation.participants(m)}
                  for m in conversation.messages}

    # the look-a-like was only ever on the second message
    assert "jane.doe@exarnple.com" not in by_message["<c1@example.com>"]
    assert "jane.doe@exarnple.com" in by_message["<c2@company.com>"]
    assert "jane.doe@exarnple.com" not in by_message["<c3@example.com>"]

    assert conversation.messages_containing_domain("exarnple.com") == [conversation.messages[1]]
    # only ever cc'd - it never sent mail into this conversation
    assert conversation.roles_for_domain("exarnple.com") == {"cc"}
    assert conversation.roles_for_domain("example.com") == {"from", "to"}


@pytest.mark.integration
def test_messages_containing_domain_counts_the_message_sender():
    """A message's own sender counts as presence even with no attributable participant rows.

    from_domain lives on the MESSAGE row, so it survives the case that broke this: participant rows
    written before message_id_hash existed are unattributable, and reading them alone reported
    "present on 0 of N" for a domain that sent N of the messages - while the same analysis said it
    had sent mail, because the role verdicts do count unattributable rows.
    """
    _record_conversation()

    # a fourth message sent BY the look-a-like, whose participant rows predate per-message tracking
    record_thread(_context(
        "<c4@exarnple.com>", "self", "<c4@exarnple.com>", "quarterly review",
        [Participant("jane.doe@exarnple.com", "exarnple.com", "from"),
         Participant("jane.doe@exarnple.com", "exarnple.com", "return_path"),
         Participant("bob@company.com", "company.com", "to")],
        message_date=datetime(2026, 3, 4, 9, 0, 0)))
    _strip_message_attribution("<c4@exarnple.com>")

    conversation = get_conversation("<c4@exarnple.com>")

    # nothing attributes a participant to message 4...
    assert conversation.participants(conversation.messages[3]) == []
    assert {p.address for p in conversation.unattributed_participants} == {
        "jane.doe@exarnple.com", "bob@company.com"}

    # ...but the message row still says who sent it, so presence is not lost
    assert conversation.messages_containing_domain("exarnple.com") == [
        conversation.messages[1], conversation.messages[3]]
    assert conversation.has_unattributed_domain("exarnple.com") is True
    assert conversation.has_unattributed_domain("example.com") is False

    # the role verdicts were never affected by attribution and must not change
    assert conversation.roles_for_domain("exarnple.com") == {"cc", "from", "return_path"}


@pytest.mark.integration
def test_get_conversation_unknown_message():
    assert get_conversation("<never-recorded@example.com>") is None
    assert get_conversation("") is None


@pytest.mark.integration
def test_get_conversation_truncates_but_keeps_the_anchor():
    _record_conversation()

    # the cap keeps the OLDEST messages so a look-a-like's entry point stays visible, but the
    # message the analyst is actually looking at must survive regardless
    conversation = get_conversation("<c3@example.com>", max_messages=1)
    assert conversation.truncated is True
    message_ids = [m.message_id for m in conversation.messages]
    assert "<c1@example.com>" in message_ids
    assert "<c3@example.com>" in message_ids


@pytest.mark.integration
def test_get_conversation_reports_how_it_was_assembled():
    _record_conversation()

    conversation = get_conversation("<c3@example.com>")
    # nothing carried threading headers, so this is the subject + shared-domain path
    assert conversation.thread_method == "self"
    assert conversation.thread_count == 3
    # company.com and example.com both span the threads and are what justified joining them
    assert "company.com" in conversation.link_domains
    # one message per joined thread - the shape a subject collision produces
    assert conversation.thread_message_counts == [1, 1, 1]


@pytest.mark.integration
def test_get_conversation_does_not_subject_merge_a_header_threaded_message():
    """A message grouped by References must not have same-subject threads merged on top of it.

    get_established_domains scores such a message against its thread ONLY, so merging here would
    show the analyst a wider conversation than the look-a-like comparison was actually made against.
    """
    # a real reply chain: root plus two replies, all sharing one thread_id
    record_thread(_context("<hdr-root@example.com>", "self", "<hdr-root@example.com>", "budget review",
                           [Participant("ceo@example.com", "example.com", "from"),
                            Participant("cfo@company.com", "company.com", "to")],
                           message_date=datetime(2026, 4, 1, 9, 0, 0)))
    for index in (1, 2):
        record_thread(_context(
            "<hdr-root@example.com>", "references", f"<hdr-{index}@company.com>", "budget review",
            [Participant("cfo@company.com", "company.com", "from"),
             Participant("ceo@example.com", "example.com", "to")],
            references="<hdr-root@example.com>",
            message_date=datetime(2026, 4, 1 + index, 9, 0, 0)))

    # an unrelated self-threaded message with the SAME subject and an overlapping domain, which the
    # subject fallback would happily absorb
    record_thread(_context("<unrelated@company.com>", "self", "<unrelated@company.com>", "budget review",
                           [Participant("intern@company.com", "company.com", "from"),
                            Participant("ceo@example.com", "example.com", "to")],
                           message_date=datetime(2026, 4, 9, 9, 0, 0)))

    conversation = get_conversation("<hdr-2@company.com>")
    assert conversation.thread_method == "headers"
    assert conversation.thread_count == 1
    assert conversation.link_domains == []
    assert "<unrelated@company.com>" not in [m.message_id for m in conversation.messages]
    assert len(conversation.messages) == 3


@pytest.mark.integration
def test_display_cap_does_not_change_the_ever_sent_verdict():
    """The cap bounds what is rendered; it must not bound the "did it ever send?" answer.

    Built from the case that exposed the bug: 60 self-threaded messages where a look-a-like sends
    exactly once, late. When the thread cap dropped that one message, roles_for_domain lost 'from'
    and the module reported "never sent mail into this conversation" about a domain that did -
    the malicious shape rendering as the benign one, stated as fact.
    """
    lookalike = "exarnple.com"
    for index in range(60):
        if index == 55:
            sender, domain = f"ops@{lookalike}", lookalike       # the single malicious send
        elif index % 2 == 0:
            sender, domain = "ops@example.com", "example.com"
        else:
            sender, domain = "ops@company.com", "company.com"

        record_thread(_context(
            f"<cap-{index:03d}@{domain}>", "self", f"<cap-{index:03d}@{domain}>", "status update",
            [Participant(sender, domain, "from"),
             Participant(sender, domain, "return_path"),
             Participant("ops@company.com", "company.com", "to")],
            message_date=datetime(2026, 1, 1, 9, 0, 0) + timedelta(days=index)))

    anchor = "<cap-059@company.com>"

    uncapped = get_conversation(anchor, max_messages=100, max_threads=100)
    assert uncapped.truncated is False
    assert "from" in uncapped.roles_for_domain(lookalike)

    # a cap tight enough that the look-a-like's one message is not displayed at all
    capped = get_conversation(anchor, max_messages=50, max_threads=10)
    assert capped.truncated is True
    assert f"<cap-055@{lookalike}>" not in [m.message_id for m in capped.messages]

    # ...and the verdict is unchanged regardless
    assert capped.roles_for_domain(lookalike) == uncapped.roles_for_domain(lookalike)
    assert f"ops@{lookalike}" in capped.addresses_for_domain(lookalike)
    assert lookalike in capped.participant_domains


@pytest.mark.integration
def test_thread_cap_keeps_the_oldest_threads():
    """Ordering before the cap is by first-seen, not by hash - otherwise which messages survive is
    unpredictable and the "oldest were kept" explanation shown to the analyst is untrue."""
    _record_conversation()

    capped = get_conversation("<c3@example.com>", max_messages=50, max_threads=2)
    kept = [m.message_id for m in capped.messages]
    assert "<c1@example.com>" in kept          # oldest sibling survives
    assert "<c3@example.com>" in kept          # anchor always survives


@pytest.mark.integration
def test_get_conversation_thread_cap_reports_truncation():
    _record_conversation()

    # every message here threads to itself, so the conversation is 3 messages across 3 threads and
    # the THREAD cap is what bites first - a smaller max_threads than max_messages silently becomes
    # the real message limit. it must still report itself as truncated, or a trimmed timeline is
    # indistinguishable from a complete one.
    conversation = get_conversation("<c3@example.com>", max_messages=50, max_threads=2)
    assert conversation.thread_count == 2
    assert len(conversation.messages) < 3
    assert conversation.truncated is True
