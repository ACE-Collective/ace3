# vim: sw=4:ts=4:et:cc=120
#
# email conversation (thread) reconstruction and the brocess-backed thread store
#
# threads are reconstructed JWZ-style: primarily from the RFC threading headers (Message-ID / In-Reply-To /
# References), falling back to normalized-subject + participant-domain overlap when those headers are missing.
# per-message metadata and per-thread participant domains are persisted in the brocess database so that a
# later message in the same thread can be compared against the domains already established in that thread.

import email.utils
import logging
import re

from collections import namedtuple
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from saq.database import execute_with_retry, get_db_connection
from saq.domain_similarity import registrable_domain
from saq.email import get_email_domain, is_local_email_domain, normalize_message_id

# matches an addr-spec wrapped in angle brackets (a single message-id token)
RE_MESSAGE_ID_TOKEN = re.compile(r"<[^<>]+>")

# leading reply/forward prefixes to strip when normalizing a subject (re:, fwd:, fw:, aw:, sv:, tr:),
# optionally followed by a bracketed counter such as "[2]"
RE_SUBJECT_PREFIX = re.compile(r"^\s*(re|fwd?|aw|sv|tr)\s*(\[\d+\])?\s*:\s*", re.IGNORECASE)
RE_WHITESPACE = re.compile(r"\s+")

# roles whose domains we score a new sender against; and the full set we record as thread participants
SENDER_ROLES = ("from", "reply_to", "return_path")

# how a conversation was assembled, as reported by get_conversation(). derived rather than stored -
# email_thread_message does not persist thread_method.
THREAD_METHOD_HEADERS = "headers"   # In-Reply-To / References grouped it; no subject merge was done
THREAD_METHOD_SELF = "self"         # nothing linked it, so same-subject + shared-domain was used

# direction values stored in email_thread_message.direction
DIRECTION_INBOUND = 0
DIRECTION_OUTBOUND = 1

# bounds on how much of a conversation get_conversation() will assemble. the brocess connection runs
# with a short query_timeout and a timeout puts the calling analysis module into cooldown, so a
# generic normalized subject ("invoice") must not be able to fan out without limit.
DEFAULT_MAX_CONVERSATION_MESSAGES = 50
# not lower than the message cap: messages with no In-Reply-To/References each get their own
# thread_id, so a self-threaded conversation has one thread PER MESSAGE and a smaller thread cap
# would silently become the real message limit.
DEFAULT_MAX_CONVERSATION_THREADS = 50

# a participant domain observed in a thread (one role of one address)
Participant = namedtuple("Participant", ["address", "domain", "role"])

# a row returned from the thread domain store, collapsed to one entry per (domain, address, role)
ThreadDomain = namedtuple("ThreadDomain", ["domain", "address", "role", "firstseendate"])

# a message recorded in the thread store, as returned by get_conversation()
ConversationMessage = namedtuple("ConversationMessage", [
    "thread_id", "message_id", "message_id_hex", "in_reply_to", "normalized_subject",
    "from_address", "from_domain", "direction", "message_date", "insert_date"])

# one participant sighting on one message
MessageParticipant = namedtuple("MessageParticipant", [
    "message_id_hex", "domain", "address", "role", "firstseendate"])


def normalize_subject(subject: Optional[str]) -> str:
    """Strip reply/forward prefixes and collapse whitespace so subjects can be matched across a thread."""
    if not subject:
        return ""

    result = subject
    # repeatedly strip prefixes - real-world subjects stack them ("Re: Fwd: Re: ...")
    for _ in range(100):
        stripped = RE_SUBJECT_PREFIX.sub("", result, count=1)
        if stripped == result:
            break
        result = stripped
    else:
        logging.error("normalize_subject: subject prefix stripping exhausted maximum iterations for subject %s", subject)
   
    return RE_WHITESPACE.sub(" ", result).strip().lower()


def parse_message_id_list(value: Optional[str]) -> list:
    """Extract all <...> message-id tokens from a header value (e.g. a References chain), in order."""
    if not value:
        return []

    return RE_MESSAGE_ID_TOKEN.findall(value)


def derive_thread_id(message_id: Optional[str], in_reply_to: Optional[str],
                     references: Optional[str]) -> tuple:
    """Derive a stable thread id from the threading headers, returning (thread_id, method).

    References is oldest-first, so References[0] is the JWZ root and groups every reply consistently
    regardless of arrival order. Falls back to In-Reply-To, then to the message's own id (a new thread).
    """
    references_list = parse_message_id_list(references)
    if references_list:
        return references_list[0], "references"

    in_reply_to_token = (parse_message_id_list(in_reply_to) or [None])[0]
    if in_reply_to_token:
        return in_reply_to_token, "in_reply_to"

    if message_id:
        return normalize_message_id(message_id), "self"

    return "", "none"


def _header_value(email_analysis, name: str) -> Optional[str]:
    """Return the first matching header value (case-insensitive) from an EmailAnalysis, or None.

    headers are read directly off the parsed header list - this is the workaround for In-Reply-To not
    being individually keyed and References being stored under a misspelled log_entry key.
    """
    for header in email_analysis.headers or []:
        if header and header[0] and header[0].lower() == name.lower():
            return header[1]

    return None


@dataclass
class ThreadContext:
    """Everything needed to record a message into the thread store and to score its sender domains."""

    thread_id: str
    thread_method: str
    message_id: Optional[str]
    in_reply_to: Optional[str]
    references: Optional[str]
    normalized_subject: str
    message_date: Optional[datetime]
    from_address: Optional[str]
    from_domain: Optional[str]
    direction: Optional[int]
    # all participant domains (from/reply_to/return_path/to/cc) recorded for the thread
    participants: list = field(default_factory=list)
    # the subset of participants we treat as suspect senders to score against established domains
    senders: list = field(default_factory=list)

    @property
    def participant_domains(self) -> set:
        return {p.domain for p in self.participants if p.domain}


@dataclass
class Conversation:
    """A recorded conversation: its messages in order, with the participants of each."""

    anchor_message_id: str
    normalized_subject: Optional[str]
    # how many thread_ids were merged into this conversation (>1 means subject-linked, see get_conversation)
    thread_count: int
    # THREAD_METHOD_HEADERS or THREAD_METHOD_SELF - how the anchor threaded, which decides whether a
    # subject merge happened at all. do not infer this from thread_count.
    thread_method: str = THREAD_METHOD_SELF
    # domains whose presence on both sides justified merging a same-subject thread in
    link_domains: list = field(default_factory=list)
    # messages contributed by each merged thread, largest first. all-ones across many threads is the
    # signature of a subject collision rather than a real conversation.
    thread_message_counts: list = field(default_factory=list)
    # domain -> roles / addresses across EVERY thread of the conversation, including any the display
    # cap trimmed. these answer "did it ever send?" and "what did it impersonate?", which must not
    # change depending on where the cap happened to fall.
    domain_roles: dict = field(default_factory=dict)
    domain_addresses: dict = field(default_factory=dict)
    messages: list = field(default_factory=list)
    # message_id_hex -> list of MessageParticipant
    participants_by_message: dict = field(default_factory=dict)
    # participants recorded before per-message tracking existed, so not attributable to a message
    unattributed_participants: list = field(default_factory=list)
    truncated: bool = False

    def participants(self, message: ConversationMessage) -> list:
        return self.participants_by_message.get(message.message_id_hex, [])

    def roles_for_domain(self, domain: str) -> set:
        """Every role this domain was seen in across the whole conversation, cap or no cap."""
        return set(self.domain_roles.get(domain, ()))

    def addresses_for_domain(self, domain: str) -> set:
        """Every address seen on this domain across the whole conversation, cap or no cap."""
        return set(self.domain_addresses.get(domain, ()))

    def messages_containing_domain(self, domain: str) -> list:
        return [m for m in self.messages
                if any(p.domain == domain for p in self.participants(m))]

    @property
    def all_participants(self) -> list:
        result = list(self.unattributed_participants)
        for participants in self.participants_by_message.values():
            result.extend(participants)

        return result

    @property
    def participant_domains(self) -> set:
        """Every domain in the conversation, including ones only present in trimmed threads.

        This is what look-a-like pairs are searched over, so capping it would mean a pair whose
        suspect side fell outside the display limit is never flagged at all.
        """
        return set(self.domain_roles) or {p.domain for p in self.all_participants if p.domain}


def _participant(address: Optional[str], role: str) -> Optional[Participant]:
    if not address:
        return None

    domain = registrable_domain(get_email_domain(address) or "")
    if not domain:
        return None

    return Participant(address=address, domain=domain, role=role)


def derive_thread_context(email_analysis) -> ThreadContext:
    """Build a ThreadContext from a parsed EmailAnalysis (used identically by the recorder and the scorer)."""
    log_entry = (email_analysis.email or {}).get("log_entry") or {}

    message_id = log_entry.get("message_id") or email_analysis.message_id
    in_reply_to = log_entry.get("in_reply_to")
    # NOTE (pulling from headers due to the typo in the log_entry key name)
    references = _header_value(email_analysis, "references")

    thread_id, thread_method = derive_thread_id(message_id, in_reply_to, references)

    normalized = normalize_subject(email_analysis.decoded_subject or email_analysis.subject)

    # message date from the Date header (falls back to None - ordering then uses insert_date)
    message_date = None
    date_header = _header_value(email_analysis, "date")
    if date_header:
        try:
            message_date = email.utils.parsedate_to_datetime(date_header)
        except (TypeError, ValueError):
            message_date = None

    # collect participants: senders we will score, plus all recipients for the reference set
    participants = []
    senders = []

    from_participant = _participant(email_analysis.mail_from_address, "from")
    reply_participant = _participant(email_analysis.reply_to_address, "reply_to")
    return_participant = _participant(
        email.utils.parseaddr(email_analysis.return_path)[1] if email_analysis.return_path else None,
        "return_path")

    for participant in (from_participant, reply_participant, return_participant):
        if participant:
            senders.append(participant)
            participants.append(participant)

    for address in (email_analysis.mail_to_addresses or []):
        participant = _participant(address, "to")
        if participant:
            participants.append(participant)

    for address in (email_analysis.cc or []):
        # cc is a list of raw header values - extract the address portion
        cc_address = email.utils.parseaddr(address)[1] if isinstance(address, str) else None
        participant = _participant(cc_address, "cc")
        if participant:
            participants.append(participant)

    from_address = from_participant.address if from_participant else None
    from_domain = from_participant.domain if from_participant else None

    direction = None
    if from_address is not None:
        direction = DIRECTION_OUTBOUND if is_local_email_domain(from_address) else DIRECTION_INBOUND

    return ThreadContext(
        thread_id=thread_id,
        thread_method=thread_method,
        message_id=normalize_message_id(message_id) if message_id else None,
        in_reply_to=in_reply_to,
        references=references,
        normalized_subject=normalized,
        message_date=message_date,
        from_address=from_address,
        from_domain=from_domain,
        direction=direction,
        participants=participants,
        senders=senders,
    )


def record_thread(context: ThreadContext) -> None:
    """Persist a message and its participant domains into the brocess thread store.

    must be called AFTER the look-a-like scoring for the same message, so that the message's own domains
    are not yet present when its sender is compared against the thread's established domains.
    """
    if not context.thread_id or not context.message_id:
        logging.debug("skipping thread store - missing thread_id or message_id")
        return

    with get_db_connection(name="brocess") as db:
        cursor = db.cursor()

        # record the message. on a duplicate (the same message reprocessed) leave the row unchanged.
        execute_with_retry(db, cursor, """
INSERT INTO email_thread_message (
    thread_id, thread_id_hash, message_id, message_id_hash, in_reply_to,
    normalized_subject, normalized_subject_hash, from_address, from_domain, direction, message_date )
VALUES (
    %s, UNHEX(SHA2(%s, 256)), %s, UNHEX(SHA2(%s, 256)), %s,
    %s, UNHEX(SHA2(%s, 256)), %s, %s, %s, %s )
ON DUPLICATE KEY UPDATE id = id""", (
            context.thread_id, context.thread_id,
            context.message_id, context.message_id,
            context.in_reply_to,
            context.normalized_subject or None, context.normalized_subject or None,
            context.from_address, context.from_domain,
            context.direction, context.message_date))

        # record each participant domain. rows are per-message (entry_hash covers the message id),
        # so re-processing the same message must leave the row alone rather than double-count it.
        for participant in context.participants:
            execute_with_retry(db, cursor, """
INSERT INTO email_thread_domain (
    thread_id, thread_id_hash, message_id_hash, domain, address, role, entry_hash, numseen, firstseendate )
VALUES (
    %s, UNHEX(SHA2(%s, 256)), UNHEX(SHA2(%s, 256)), %s, %s, %s,
    UNHEX(SHA2(CONCAT_WS(0x1f, %s, %s, %s, %s), 256)), 1, NOW() )
ON DUPLICATE KEY UPDATE id = id""", (
                context.thread_id, context.thread_id,
                context.message_id,
                participant.domain, participant.address, participant.role,
                context.message_id, participant.domain, participant.address, participant.role))

        db.commit()


def _collapse_thread_domains(rows) -> list:
    """Collapse per-message participant rows into one ThreadDomain per (domain, address, role).

    email_thread_domain holds one row per message a participant appeared on, so a participant on
    five messages of a thread returns five rows. the established-domain set that look-a-like scoring
    compares against is a set of domains, not sightings, and firstseendate must stay the EARLIEST
    sighting - so collapse here rather than in SQL (keeps the queries index-only and avoids grouping
    on TEXT columns).
    """
    collapsed = {}
    for domain, address, role, firstseendate in rows:
        key = (domain, address, role)
        existing = collapsed.get(key)
        if existing is None:
            collapsed[key] = ThreadDomain(domain, address, role, firstseendate)
            continue

        # keep the earliest firstseendate; a NULL sorts as unknown and never wins over a real date
        if firstseendate is not None and (existing.firstseendate is None
                                          or firstseendate < existing.firstseendate):
            collapsed[key] = ThreadDomain(domain, address, role, firstseendate)

    return list(collapsed.values())


def get_established_thread_domains(thread_id: str) -> list:
    """Return the participant domains already recorded for a thread (header-threaded path)."""
    if not thread_id:
        return []

    with get_db_connection(name="brocess") as db:
        cursor = db.cursor()
        cursor.execute("""
SELECT domain, address, role, firstseendate FROM email_thread_domain
WHERE thread_id_hash = UNHEX(SHA2(%s, 256))""", (thread_id,))
        return _collapse_thread_domains(cursor.fetchall())


def _threads_overlapping_domains(rows, current_domains: set) -> dict:
    """Group (thread_hex, domain, address, role, firstseendate) rows by thread, keeping only threads
    that share at least one participant domain with current_domains.

    this is the conversation-scoping rule: a shared subject line alone is not enough to merge two
    threads into one conversation, or unrelated mail with a generic subject would all collapse
    together. shared by the established-domain fallback and the conversation timeline.
    """
    by_thread = {}
    for thread_hex, domain, address, role, firstseendate in rows:
        by_thread.setdefault(thread_hex, []).append((domain, address, role, firstseendate))

    return {thread_hex: domains for thread_hex, domains in by_thread.items()
            if current_domains.intersection({d[0] for d in domains})}


def get_subject_fallback_domains(normalized_subject: str, current_domains: set) -> list:
    """Return participant domains from prior same-subject threads that share a domain with this message.

    this is the fallback when threading headers are absent. requiring a shared participant domain prevents
    unrelated messages that merely share a subject line from being merged into one conversation.
    """
    if not normalized_subject:
        return []

    with get_db_connection(name="brocess") as db:
        cursor = db.cursor()
        cursor.execute("""
SELECT HEX(d.thread_id_hash), d.domain, d.address, d.role, d.firstseendate
FROM email_thread_domain d
WHERE d.thread_id_hash IN (
    SELECT m.thread_id_hash FROM email_thread_message m
    WHERE m.normalized_subject_hash = UNHEX(SHA2(%s, 256)) )""", (normalized_subject,))
        rows = cursor.fetchall()

    result = []
    for domains in _threads_overlapping_domains(rows, current_domains).values():
        result.extend(domains)

    return _collapse_thread_domains(result)


def get_established_domains(context: ThreadContext) -> list:
    """Return the established domains to score this message's senders against, scoped to its conversation.

    uses the header-threaded set when the message links to a thread; otherwise falls back to same-subject
    threads that share a participant domain. never compares across unrelated conversations.
    """
    if context.thread_method in ("references", "in_reply_to"):
        return get_established_thread_domains(context.thread_id)

    return get_subject_fallback_domains(context.normalized_subject, context.participant_domains)


def get_thread_message_count(thread_id: str) -> int:
    """Return how many messages have been recorded for a thread."""
    if not thread_id:
        return 0

    with get_db_connection(name="brocess") as db:
        cursor = db.cursor()
        cursor.execute("""
SELECT COUNT(*) FROM email_thread_message WHERE thread_id_hash = UNHEX(SHA2(%s, 256))""", (thread_id,))
        for row in cursor:
            return int(row[0]) if row[0] is not None else 0

        return 0


def get_conversation(message_id: str,
                     max_messages: int = DEFAULT_MAX_CONVERSATION_MESSAGES,
                     max_threads: int = DEFAULT_MAX_CONVERSATION_THREADS) -> Optional[Conversation]:
    """Return the recorded conversation containing message_id, or None if it was never recorded.

    Scope mirrors get_established_domains, so the timeline shows the conversation the look-a-like
    comparison was actually made against:

      - anchor threaded by References / In-Reply-To -> its thread ONLY. the headers already grouped
        the conversation and merging same-subject threads on top would show more than was scored.
      - anchor threaded to itself -> its thread PLUS same-subject threads sharing a participant
        domain. this is not an edge case: a message with no threading headers threads to itself, so
        a reply chain of such messages lands in one thread_id PER MESSAGE and the thread alone is a
        single row.

    thread_method is not persisted, so it is recovered from the stored ids: a message whose thread_id
    is its own message_id did not link to a parent (derive_thread_id's "self" branch), anything else
    resolved through References or In-Reply-To.
    """
    if not message_id:
        return None

    with get_db_connection(name="brocess") as db:
        cursor = db.cursor()

        cursor.execute("""
SELECT HEX(thread_id_hash), normalized_subject, thread_id, message_id FROM email_thread_message
WHERE message_id_hash = UNHEX(SHA2(%s, 256)) LIMIT 1""", (message_id,))
        anchor = cursor.fetchone()
        if anchor is None:
            logging.debug("no recorded thread message for %s", message_id)
            return None

        anchor_thread_hex, normalized_subject, anchor_thread_id, anchor_message_id = anchor
        header_threaded = anchor_thread_id != anchor_message_id
        thread_method = THREAD_METHOD_HEADERS if header_threaded else THREAD_METHOD_SELF

        thread_hexes, threads_capped, link_domains, all_roles, all_addresses = \
            _resolve_conversation_threads(cursor, anchor_thread_hex, normalized_subject, max_threads,
                                          subject_merge=not header_threaded)

        placeholders = ", ".join(["UNHEX(%s)"] * len(thread_hexes))

        # one extra row so a truncated conversation can be reported as such
        cursor.execute(f"""
SELECT thread_id, message_id, HEX(message_id_hash), in_reply_to, normalized_subject,
       from_address, from_domain, direction, message_date, insert_date
FROM email_thread_message
WHERE thread_id_hash IN ({placeholders})
ORDER BY message_date IS NULL, message_date, insert_date
LIMIT %s""", (*thread_hexes, max_messages + 1))
        message_rows = [ConversationMessage(*row) for row in cursor.fetchall()]

        cursor.execute(f"""
SELECT HEX(message_id_hash), domain, address, role, firstseendate
FROM email_thread_domain
WHERE thread_id_hash IN ({placeholders})""", tuple(thread_hexes))
        participant_rows = cursor.fetchall()

    messages_capped = len(message_rows) > max_messages
    if messages_capped:
        logging.info("conversation for %s truncated to %d messages", message_id, max_messages)
        message_rows = message_rows[:max_messages]

        # the anchor is the message the analyst is looking at - never let the cap drop it
        if not any(m.message_id == message_id for m in message_rows):
            message_rows.append(_load_message(message_id))

    # either cap means the analyst is not looking at the whole conversation, and they have to be
    # told: a silently trimmed timeline reads exactly like a complete one. the thread cap is the
    # one that usually bites, because a conversation of messages with no In-Reply-To/References
    # produces one thread per message.
    truncated = messages_capped or threads_capped

    participants_by_message = {}
    unattributed = []
    for message_id_hex, domain, address, role, firstseendate in participant_rows:
        # fold the retained threads in too - covers the header-threaded path, where no subject scan
        # ran, and is a no-op for the merged path where these threads were already counted
        all_roles.setdefault(domain, set()).add(role)
        all_addresses.setdefault(domain, set()).add(address)

        participant = MessageParticipant(message_id_hex, domain, address, role, firstseendate)
        if message_id_hex is None:
            # written before per-message participant recording - see sql/tools/alter_email_thread_domain_message_id.sql
            unattributed.append(participant)
        else:
            participants_by_message.setdefault(message_id_hex, []).append(participant)

    messages = [m for m in message_rows if m is not None]

    per_thread = {}
    for message in messages:
        per_thread[message.thread_id] = per_thread.get(message.thread_id, 0) + 1

    return Conversation(
        anchor_message_id=message_id,
        normalized_subject=normalized_subject,
        thread_count=len(thread_hexes),
        thread_method=thread_method,
        link_domains=link_domains,
        domain_roles=all_roles,
        domain_addresses=all_addresses,
        thread_message_counts=sorted(per_thread.values(), reverse=True),
        messages=messages,
        participants_by_message=participants_by_message,
        unattributed_participants=unattributed,
        truncated=truncated)


def _resolve_conversation_threads(cursor, anchor_thread_hex: str, normalized_subject: Optional[str],
                                  max_threads: int, subject_merge: bool = True) -> tuple:
    """Resolve the conversation's threads.

    Returns (thread hashes to DISPLAY, whether the cap trimmed any, domains that justified the merge,
    roles per domain across EVERY qualifying thread, addresses per domain across every qualifying
    thread).

    The last two are deliberately uncapped. max_threads bounds how much conversation is rendered; it
    must not bound the "did this domain ever send?" verdict, because dropping the single message
    where a look-a-like sent flips that answer from malicious to benign and the finding is stated as
    fact. Costs nothing extra - the rows are already fetched here, before any trimming.

    subject_merge=False keeps the conversation to the anchor's own thread, which is correct when the
    threading headers already grouped it.
    """
    if not subject_merge or not normalized_subject:
        return [anchor_thread_hex], False, [], {}, {}

    cursor.execute("""
SELECT HEX(d.thread_id_hash), d.domain, d.address, d.role, d.firstseendate
FROM email_thread_domain d
WHERE d.thread_id_hash IN (
    SELECT m.thread_id_hash FROM email_thread_message m
    WHERE m.normalized_subject_hash = UNHEX(SHA2(%s, 256)) )""", (normalized_subject,))
    rows = cursor.fetchall()

    anchor_domains = {row[1] for row in rows if row[0] == anchor_thread_hex}
    if not anchor_domains:
        return [anchor_thread_hex], False, [], {}, {}

    overlapping = _threads_overlapping_domains(rows, anchor_domains)

    # the verdict inputs, over every qualifying thread and therefore immune to the cap below
    all_roles, all_addresses = {}, {}
    for thread_domains in overlapping.values():
        for domain, address, role, _ in thread_domains:
            all_roles.setdefault(domain, set()).add(role)
            all_addresses.setdefault(domain, set()).add(address)

    # Order by the thread's earliest MESSAGE date, oldest first, so the cap keeps the start of the
    # conversation - matching the message cap's ORDER BY, and keeping any look-a-like's entry point
    # visible. Sorting the hex hashes instead (as this used to) drops threads in an order nobody can
    # predict or explain, which made "which messages survived" effectively random.
    #
    # Deliberately NOT email_thread_domain.firstseendate: that is ingest time, so anything recorded
    # in one batch - a backfill, or a test - carries near-identical values and the sort degenerates
    # back to the hash tiebreaker.
    cursor.execute("""
SELECT HEX(thread_id_hash), MIN(message_date), MIN(insert_date) FROM email_thread_message
WHERE normalized_subject_hash = UNHEX(SHA2(%s, 256))
GROUP BY thread_id_hash""", (normalized_subject,))
    thread_dates = {row[0]: (row[1], row[2]) for row in cursor.fetchall()}

    def _oldest_first(thread_hex):
        message_date, insert_date = thread_dates.get(thread_hex, (None, None))
        # mirror the message query: a missing message_date sorts last, then fall back to insert_date
        return (message_date is None, message_date, insert_date, thread_hex)

    siblings = sorted(overlapping, key=_oldest_first)
    if anchor_thread_hex not in siblings:
        siblings.insert(0, anchor_thread_hex)

    # the domains that actually justified pulling the other threads in. a merge resting on one
    # ubiquitous domain (our own, say) plus a generic subject is how unrelated mail gets stitched
    # into one "conversation", so the analyst has to be able to see what the link was.
    link_domains = sorted({domain
                           for thread_hex, domains in overlapping.items()
                           if thread_hex != anchor_thread_hex
                           for domain, _, _, _ in domains} & anchor_domains)

    if len(siblings) <= max_threads:
        return siblings, False, link_domains, all_roles, all_addresses

    logging.info("same-subject conversation spans %d threads, capping display at %d "
                 "(roles and addresses are still computed over all of them)",
                 len(siblings), max_threads)
    # keep the anchor thread; the cap only trims siblings, oldest-first per the sort above
    trimmed = [anchor_thread_hex] + [t for t in siblings if t != anchor_thread_hex][:max_threads - 1]
    return trimmed, True, link_domains, all_roles, all_addresses


def _load_message(message_id: str) -> Optional[ConversationMessage]:
    """Return a single recorded message by message id, or None."""
    with get_db_connection(name="brocess") as db:
        cursor = db.cursor()
        cursor.execute("""
SELECT thread_id, message_id, HEX(message_id_hash), in_reply_to, normalized_subject,
       from_address, from_domain, direction, message_date, insert_date
FROM email_thread_message
WHERE message_id_hash = UNHEX(SHA2(%s, 256)) LIMIT 1""", (message_id,))
        row = cursor.fetchone()
        return ConversationMessage(*row) if row else None
