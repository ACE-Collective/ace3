# vim: sw=4:ts=4:et:cc=120
#
# email conversation (thread) timeline
#
# renders the conversation a message belongs to as a timeline, so an analyst triaging a look-a-like
# domain alert can see where and when the domain entered the conversation instead of searching the
# alerting message for a string that is frequently not in it.
#
# this module is display only. it raises no detections, adds no tags and adds no observables - the
# whole point is to explain an alert that already exists without growing the analysis tree.
#

import logging

from typing import Optional, Type

from pydantic import Field

from saq.analysis.analysis import Analysis
from saq.analysis.presenter.analysis_presenter import (
    AnalysisPresenter,
    register_analysis_presenter,
)
from saq.constants import F_MESSAGE_ID, SUMMARY_DETAIL_FORMAT_MD, AnalysisExecutionResult
from saq.domain_similarity import compare_domains, compare_local_parts
from saq.email import normalize_message_id
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from saq.modules.email.conversation import (
    DEFAULT_MAX_CONVERSATION_MESSAGES,
    DEFAULT_MAX_CONVERSATION_THREADS,
    DIRECTION_OUTBOUND,
    SENDER_ROLES,
    Conversation,
    get_conversation,
)

# Roles that mean mail actually ORIGINATED from a domain. Deliberately narrower than
# conversation.SENDER_ROLES, which also contains reply_to: Reply-To only says where replies are
# directed, so a domain appearing solely as Reply-To never sent anything. Conflating the two reports
# "sent mail into this conversation" for a domain that did not, which pushes an analyst toward
# escalating exactly the benign case (two related domains sharing one reply address).
ORIGIN_ROLES = ("from", "return_path")

KEY_ANCHOR_MESSAGE_ID = "anchor_message_id"
KEY_NORMALIZED_SUBJECT = "normalized_subject"
KEY_THREAD_COUNT = "thread_count"
KEY_THREAD_METHOD = "thread_method"
KEY_LINK_DOMAINS = "link_domains"
KEY_THREAD_MESSAGE_COUNTS = "thread_message_counts"
KEY_TRUNCATED = "truncated"
KEY_MESSAGES = "messages"
KEY_LOOKALIKES = "lookalikes"
KEY_UNATTRIBUTED = "unattributed_participants"


class EmailThreadAnalysis(Analysis):
    """The conversation a message belongs to, as a timeline, with any look-a-like domain pairs in it."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_ANCHOR_MESSAGE_ID: None,
            KEY_NORMALIZED_SUBJECT: None,
            KEY_THREAD_COUNT: 0,
            KEY_THREAD_METHOD: None,
            KEY_LINK_DOMAINS: [],
            KEY_THREAD_MESSAGE_COUNTS: [],
            KEY_TRUNCATED: False,
            KEY_MESSAGES: [],
            KEY_LOOKALIKES: [],
            KEY_UNATTRIBUTED: [],
        }

    @property
    def anchor_message_id(self):
        return self.details[KEY_ANCHOR_MESSAGE_ID]

    @property
    def normalized_subject(self):
        return self.details[KEY_NORMALIZED_SUBJECT]

    @property
    def thread_count(self):
        return self.details[KEY_THREAD_COUNT]

    @property
    def thread_method(self):
        """THREAD_METHOD_HEADERS or THREAD_METHOD_SELF - how this conversation was assembled."""
        return self.details[KEY_THREAD_METHOD]

    @property
    def link_domains(self):
        return self.details[KEY_LINK_DOMAINS]

    @property
    def thread_message_counts(self):
        return self.details[KEY_THREAD_MESSAGE_COUNTS]

    @property
    def truncated(self):
        return self.details[KEY_TRUNCATED]

    @property
    def messages(self):
        return self.details[KEY_MESSAGES]

    @property
    def lookalikes(self):
        return self.details[KEY_LOOKALIKES]

    @property
    def unattributed_participants(self):
        return self.details[KEY_UNATTRIBUTED]

    def generate_summary(self):
        if not self.messages:
            return None

        result = f"Email Thread Analysis: {len(self.messages)} message"
        if len(self.messages) != 1:
            result += "s"

        dates = [m["date"] for m in self.messages if m["date"]]
        if dates:
            result += f", {dates[0]} to {dates[-1]}"

        if self.lookalikes:
            # lead with the most decisive fact rather than the count
            headline = self.lookalikes[0]
            if headline["ever_sent"]:
                result += f" - {headline['domain']} sent mail into this conversation"
            elif headline["ever_reply_to"]:
                result += f" - {headline['domain']} never sent mail, but replies were directed to it"
            else:
                result += f" - {headline['domain']} never sent mail into this conversation"

        return result


class EmailThreadAnalyzerConfig(AnalysisModuleConfig):
    max_messages: int = Field(
        default=DEFAULT_MAX_CONVERSATION_MESSAGES,
        description="maximum number of conversation messages to assemble into the timeline")
    max_threads: int = Field(
        default=DEFAULT_MAX_CONVERSATION_THREADS,
        description="maximum number of subject-linked threads to merge into a single conversation")
    max_recipients_displayed: int = Field(
        default=8,
        description="maximum number of recipients to list per timeline row before summarizing the rest")


class EmailThreadAnalyzer(AnalysisModule):
    config: EmailThreadAnalyzerConfig

    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return EmailThreadAnalyzerConfig

    def verify_environment(self):
        pass

    @property
    def generated_analysis_type(self):
        return EmailThreadAnalysis

    @property
    def valid_observable_types(self):
        return F_MESSAGE_ID

    def get_presenter_class(self) -> Type[AnalysisPresenter]:
        return EmailThreadAnalysisPresenter

    def execute_analysis(self, message_id) -> AnalysisExecutionResult:
        # brocess runs with a short query_timeout and a timeout drops the module into cooldown
        if self._context.cooldown_timeout:
            logging.debug("%s on cooldown - not checking", self)
            return AnalysisExecutionResult.COMPLETED

        # the thread store keys on the normalized (angle-bracketed) form
        normalized = normalize_message_id(message_id.value)

        try:
            conversation = get_conversation(normalized,
                                            max_messages=self.config.max_messages,
                                            max_threads=self.config.max_threads)
        except Exception as e:
            logging.error("unable to query the brocess thread store for %s: %s", normalized, e)
            self.enter_cooldown()
            return AnalysisExecutionResult.COMPLETED

        # not recorded: thread recording disabled, or the message predates it
        if conversation is None or not conversation.messages:
            return AnalysisExecutionResult.COMPLETED

        analysis = self.create_analysis(message_id)
        assert isinstance(analysis, EmailThreadAnalysis)

        analysis.details[KEY_ANCHOR_MESSAGE_ID] = normalized
        analysis.details[KEY_NORMALIZED_SUBJECT] = conversation.normalized_subject
        analysis.details[KEY_THREAD_COUNT] = conversation.thread_count
        analysis.details[KEY_THREAD_METHOD] = conversation.thread_method
        analysis.details[KEY_LINK_DOMAINS] = conversation.link_domains
        analysis.details[KEY_THREAD_MESSAGE_COUNTS] = conversation.thread_message_counts
        analysis.details[KEY_TRUNCATED] = conversation.truncated
        analysis.details[KEY_LOOKALIKES] = _build_lookalikes(conversation, normalized)
        analysis.details[KEY_MESSAGES] = _build_timeline(
            conversation, normalized,
            {entry["domain"] for entry in analysis.details[KEY_LOOKALIKES]},
            self.config.max_recipients_displayed)
        analysis.details[KEY_UNATTRIBUTED] = sorted(
            {p.address for p in conversation.unattributed_participants})

        # the full timeline lives on the drill-down page, but the findings that actually decide the
        # alert go inline in the tree - summary details on an Analysis render there directly
        findings = _build_findings(analysis)
        if findings:
            analysis.add_summary_detail(header="Email conversation",
                                        content=findings,
                                        format=SUMMARY_DETAIL_FORMAT_MD)

        return AnalysisExecutionResult.COMPLETED


def _format_date(value) -> Optional[str]:
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else None


def _build_findings(analysis: EmailThreadAnalysis) -> Optional[str]:
    """Render the decisive facts as markdown for inline display in the alert tree.

    deliberately sentences rather than a table: this is the part an analyst reads before deciding
    whether to open the full timeline at all.
    """
    if not analysis.lookalikes:
        return None

    lines = []
    for entry in analysis.lookalikes:
        # the blank line matters: markdown only starts a list after a paragraph when one separates
        # them, otherwise every bullet is swallowed into a single run-on paragraph
        lines.append(f"**{entry['domain']}** (looks like {entry['counterpart']})")
        lines.append("")

        if entry["ever_sent"]:
            lines.append(f"- Sent mail into this conversation - seen as {', '.join(entry['roles'])}.")
        elif entry["ever_reply_to"]:
            lines.append(f"- Never sent mail into this conversation, but replies were directed to it "
                         f"(Reply-To) - seen as {', '.join(entry['roles'])}.")
        else:
            lines.append(f"- Never sent mail into this conversation - only ever "
                         f"{', '.join(entry['roles'])}. No mail was received from this domain here.")

        if entry["shared_reply_to"]:
            lines.append(f"- Messages from **both** domains direct replies to "
                         f"{', '.join(entry['shared_reply_to'])} - check whether one sender runs both "
                         f"domains before treating this as impersonation.")
        elif entry["reply_to_addresses"]:
            lines.append(f"- Replies are directed to {', '.join(entry['reply_to_addresses'])}, from "
                         f"one side of the pair only - replies leave this conversation for the "
                         f"look-a-like domain. This is not the shared-operator pattern.")

        presence = f"- Present on {entry['message_count']} of {entry['total_messages']} messages"
        if entry["introduced_on"]:
            presence += f", introduced {entry['introduced_on']}"
            if entry["introduced_by_address"]:
                presence += f" by {entry['introduced_by_address']}"
        lines.append(presence + ".")

        if not entry["present_in_anchor_message"]:
            lines.append("- Not present in the message this alert fired on; it comes from earlier "
                         "messages in the conversation.")

        for item in entry["impersonations"]:
            qualifier = "identical" if item["exact_local_part"] else "similar"
            lines.append(f"- {item['address']} has an {qualifier} local part to "
                         f"{item['impersonates']}.")

        lines.append("")

    return "\n".join(lines).strip()


def _build_timeline(conversation: Conversation, anchor_message_id: str, lookalike_domains: set,
                    max_recipients: int) -> list:
    """Build one timeline row per message in the conversation."""
    timeline = []
    for index, message in enumerate(conversation.messages, start=1):
        participants = conversation.participants(message)

        by_address = {p.address: p.domain for p in participants if p.role not in SENDER_ROLES}
        present = sorted({p.domain for p in participants if p.domain in lookalike_domains})

        # Reply-To / Return-Path are sender-side roles, so they land in neither the From column nor
        # Recipients and would otherwise be recorded but never shown. They matter: two look-a-like
        # domains that funnel replies to the same address are one operator, and that is often the
        # fastest way to dispose of the alert.
        other_senders = sorted(
            ({"address": p.address, "role": p.role,
              "is_lookalike": p.domain in lookalike_domains}
             for p in participants
             if p.role in SENDER_ROLES and p.address != message.from_address),
            key=lambda s: (not s["is_lookalike"], s["role"], s["address"]))

        # flag the look-a-like addresses individually rather than only naming the domain: the whole
        # difficulty of these alerts is that the real and the look-a-like address sit side by side in
        # one recipient list and read identically. sort the flagged ones first so they are not
        # buried behind a "+N more" cut.
        recipients = sorted(
            ({"address": address, "is_lookalike": domain in lookalike_domains}
             for address, domain in by_address.items()),
            key=lambda r: (not r["is_lookalike"], r["address"]))

        timeline.append({
            "index": index,
            "message_id": message.message_id,
            "date": _format_date(message.message_date or message.insert_date),
            "date_is_estimated": message.message_date is None,
            "direction": "outbound" if message.direction == DIRECTION_OUTBOUND else "inbound",
            "from_address": message.from_address,
            "from_domain": message.from_domain,
            "from_is_lookalike": message.from_domain in lookalike_domains,
            "other_senders": other_senders,
            "recipients": recipients[:max_recipients],
            "recipients_omitted": max(0, len(recipients) - max_recipients),
            "lookalike_domains_present": present,
            "is_anchor": message.message_id == anchor_message_id,
        })

    return timeline


def _build_lookalikes(conversation: Conversation, anchor_message_id: str) -> list:
    """Find look-a-like domain pairs among the conversation's participants and describe each one.

    computed here rather than read off the alerting hunt so the analysis stands on its own and works
    for any email alert. this is annotation, not detection - no hunt tuning is consulted and nothing
    is tagged, so a pair surfacing here cannot change a disposition on its own.
    """
    domains = sorted(conversation.participant_domains)
    anchor = next((m for m in conversation.messages if m.message_id == anchor_message_id), None)
    anchor_domains = {p.domain for p in conversation.participants(anchor)} if anchor else set()

    entries = []
    for i, suspect in enumerate(domains):
        for reference in domains[i + 1:]:
            result = compare_domains(suspect, reference)
            if not result.is_similar:
                continue

            first, second = sorted((suspect, reference),
                                   key=lambda d: _suspect_rank(conversation, d))
            entries.append(_describe_lookalike(conversation, first, second, result, anchor_domains))

    # never-sent pairs first: those are the ones an analyst can dispose of quickly
    entries.sort(key=lambda e: (e["ever_sent"], -e["jaro_winkler"]))
    return entries


def _suspect_rank(conversation: Conversation, domain: str) -> tuple:
    """Sort key deciding which half of a similar pair gets named as the look-a-like. Lower = suspect.

    Naming the wrong side is actively misleading - the header reads "<legit> looks like <fake>" - so
    this cannot fall through to alphabetical order. A Cyrillic homoglyph sorts after its ASCII twin,
    which is exactly how the real domain ended up being labelled the imposter.

    In order: a domain that never sent is the anomaly worth calling out; otherwise the one that
    turned up LATER is the newcomer to an established conversation; then the one on fewer messages.
    """
    containing = conversation.messages_containing_domain(domain)
    first_seen_index = conversation.messages.index(containing[0]) if containing else len(conversation.messages)

    return (_ever_sent(conversation, domain), -first_seen_index, len(containing), domain)


def _ever_sent(conversation: Conversation, domain: str) -> bool:
    """Did mail ever actually ORIGINATE from this domain anywhere in the conversation?"""
    return bool(conversation.roles_for_domain(domain).intersection(ORIGIN_ROLES))


def _ever_reply_to(conversation: Conversation, domain: str) -> bool:
    """Were replies ever directed to this domain without it having sent anything?"""
    return "reply_to" in conversation.roles_for_domain(domain)


def _reply_to_addresses(conversation: Conversation, *domains) -> list:
    """Every Reply-To address on the given domains, regardless of which side sent the message.

    Scoped to the visible messages rather than the uncapped set: unlike roles, this is paired with
    "which message introduced it", so reporting an address whose message is not in the timeline
    would leave the analyst nothing to check.
    """
    return sorted({p.address for p in conversation.all_participants
                   if p.role == "reply_to" and p.domain in domains})


def _reply_tos_sent_from(conversation: Conversation, from_domain: str) -> set:
    """Reply-To addresses carried by the messages this domain actually sent."""
    result = set()
    for message in conversation.messages:
        if message.from_domain != from_domain:
            continue

        result |= {p.address for p in conversation.participants(message) if p.role == "reply_to"}

    return result


def _shared_reply_to(conversation: Conversation, domain: str, counterpart: str) -> list:
    """Reply-To addresses that messages from BOTH sides point at.

    Requiring both sides is the whole point. One operator running two domains points every message,
    from either domain, at a single reply address. A single side redirecting replies to the other
    domain is the opposite finding - replies leaving the real conversation.
    """
    return sorted(_reply_tos_sent_from(conversation, domain)
                  & _reply_tos_sent_from(conversation, counterpart))


def _describe_lookalike(conversation: Conversation, domain: str, counterpart: str, result,
                        anchor_domains: set) -> dict:
    """Describe one look-a-like domain: how it entered the conversation and what it has done since."""
    containing = conversation.messages_containing_domain(domain)
    introduced_by = containing[0] if containing else None

    # uncapped: an impersonating address that only appears in a trimmed thread must still be found
    addresses = sorted(conversation.addresses_for_domain(domain))
    counterpart_addresses = sorted(conversation.addresses_for_domain(counterpart))

    # which real participant, if any, is this domain's address impersonating
    impersonations = []
    for address in addresses:
        for counterpart_address in counterpart_addresses:
            local_result = compare_local_parts(address, counterpart_address)
            if not local_result.is_similar:
                continue

            impersonations.append({
                "address": address,
                "impersonates": counterpart_address,
                "exact_local_part": local_result.is_exact,
            })

    return {
        "domain": domain,
        "counterpart": counterpart,
        "damerau_levenshtein": result.damerau_levenshtein,
        "jaro_winkler": result.jaro_winkler,
        "skeleton_equal": result.skeleton_equal,
        "techniques": list(result.techniques),
        "addresses": addresses,
        "roles": sorted(conversation.roles_for_domain(domain)),
        "ever_sent": _ever_sent(conversation, domain),
        "ever_reply_to": _ever_reply_to(conversation, domain),
        # every reply-to address on either side of the pair, whoever sent the message
        "reply_to_addresses": _reply_to_addresses(conversation, domain, counterpart),
        # only those carried by messages sent from BOTH sides. that is the one-operator signal; a
        # reply-to used by a single side is the opposite - a redirect out of the conversation - so
        # these must not be conflated or the display argues for exoneration on the suspicious case.
        "shared_reply_to": _shared_reply_to(conversation, domain, counterpart),
        "message_count": len(containing),
        "total_messages": len(conversation.messages),
        "introduced_by_address": introduced_by.from_address if introduced_by else None,
        "introduced_on": _format_date(
            (introduced_by.message_date or introduced_by.insert_date) if introduced_by else None),
        "present_in_anchor_message": domain in anchor_domains,
        "impersonations": impersonations,
    }


class EmailThreadAnalysisPresenter(AnalysisPresenter):
    """Presenter for EmailThreadAnalysis."""

    @property
    def template_path(self) -> str:
        return "analysis/email_thread.html"


register_analysis_presenter(EmailThreadAnalysis, EmailThreadAnalysisPresenter)
