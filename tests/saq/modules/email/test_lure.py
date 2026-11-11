import io
import logging
import os
from email.message import EmailMessage
from pathlib import Path

import pikepdf
import pytest

from saq.analysis.root import RootAnalysis, load_root
from saq.configuration.config import get_analysis_module_config, get_config
from saq.constants import ANALYSIS_TYPE_MAILBOX, DIRECTIVE_CRAWL, F_FILE, F_URL, AnalysisExecutionResult
from saq.engine.core import Engine
from saq.engine.enums import EngineExecutionMode
from saq.modules.email import lure
from saq.modules.email.lure import (
    SOURCE_ATTACHMENT,
    SOURCE_BODY,
    SOURCE_QR,
    carried_urls,
    fold_carried_urls,
    is_http_url,
    Anchor,
    Candidate,
    CandidateCollector,
    LureURLAnalysis,
    LureURLAnalyzer,
    LureURLSettings,
    LureURLWeights,
    load_lure_settings,
    build_lure_urls,
    find_phrase,
    is_sign_off,
    parse_html_body,
    parse_text_body,
    phrase_around,
    reason_segments,
    score_candidates,
    sender_domains,
)
from saq.modules.email.rfc822 import EmailAnalysis
from saq.modules.file_analysis.pdf import PDFAnalysis, PDFLinkTextAnalysis
from saq.modules.file_analysis.qrcode import QRCodeAnalysis
from saq.modules.file_analysis.url_extraction import URLExtractionAnalysis
from saq.modules.phishkit import PhishkitAnalysis
from saq.modules.adapter import AnalysisModuleAdapter
from saq.util.uuid import get_storage_dir
from tests.saq.test_util import create_test_context

SENDER = "billing@sender.example.com"
RECIPIENT = "recipient@internal.example.org"

LURE = "https://evil.example.net/doc/view?id=1"
PRIVACY = "https://www.sender.example.com/privacy"
UNSUBSCRIBE = "https://www.sender.example.com/unsubscribe?u=1"
LOGO = "https://cdn.sender.example.com/logo.png"

TRACKER = ("https://tracker.example.com/click/1?id=7"
           "&rUrl=https%3A%2F%2Fevil.example.net%2Flogin&rUrl=https%3A%2F%2Fdecoy.example.org%2Fhome")

LURE_HTML = f"""<html><body>
<img src="{LOGO}">
<p>A document has been shared with you.</p>
<table><tr><td bgcolor="#0078d4"><a href="{LURE}" style="color:#ffffff">Review Document</a></td></tr></table>
<p><a href="{PRIVACY}">Privacy</a> | <a href="{UNSUBSCRIBE}">Unsubscribe</a></p>
</body></html>"""

SETTINGS = LureURLSettings(
    call_to_action_keywords=["review", "view", "sign"],
    noise_keywords=["unsubscribe", "privacy"],
    benign_domains=["fonts.googleapis.com"],
)


#
# body parsing
#

@pytest.mark.unit
def test_parse_html_body_anchors():
    anchors = parse_html_body(LURE_HTML + """
        <a href="https://img.example.net/x"><img src="https://img.example.net/x.png" alt="Open"></a>
        <form action="https://form.example.net/post"><input type="submit"></form>
        <a class="btn-primary" href="https://button.example.net/">Sign</a>
        <a href="  ">empty</a>""", SETTINGS).anchors

    assert anchors[LURE] == Anchor(text="Review Document", button=True, position=0)
    assert anchors[PRIVACY] == Anchor(text="Privacy", button=False, position=1)
    assert anchors[UNSUBSCRIBE].position == 2
    assert anchors["https://img.example.net/x"].text == "[image: Open]"
    assert "https://form.example.net/post" in anchors
    assert anchors["https://button.example.net/"].button is True
    # an image is a resource, not a link
    assert LOGO not in anchors


SIGNATURE_LINK = "https://www.estimating.example.org"
EARLIER = "https://projects.example.org/bid/42"
EARLIER_SIGNATURE = "https://www.example.org"

# a reply in a thread: the newest message, then the earlier one Outlook quotes under its reply header
THREAD_HTML = f"""<html><body>
<p>Hi all,</p>
<p>Please review the attached bid documents and confirm by Friday.</p>
<p>Respectfully,</p>
<p>Pat Doe<br>Estimator</p>
<p><a href="{SIGNATURE_LINK}">signature</a></p>
<div id="divRplyFwdMsg"><b>From:</b> Sam Roe &lt;sam@example.org&gt;<br><b>Sent:</b> Monday</div>
<p>Here is the <a href="{EARLIER}">project page</a>.</p>
<p>Regards,<br>Sam</p>
<p><a href="{EARLIER_SIGNATURE}">www.example.org</a></p>
</body></html>"""


@pytest.mark.unit
def test_parse_html_body_thread():
    body = parse_html_body(THREAD_HTML, SETTINGS)

    assert (body.anchors[SIGNATURE_LINK].signature, body.anchors[SIGNATURE_LINK].quoted) == (True, False)
    # a new message ends the signature block above it
    assert (body.anchors[EARLIER].signature, body.anchors[EARLIER].quoted) == (False, True)
    # and each message has its own
    assert (body.anchors[EARLIER_SIGNATURE].signature, body.anchors[EARLIER_SIGNATURE].quoted) == (True, True)
    assert "Please review the attached bid documents and confirm by Friday." in body.newest_text
    assert "Here is the" not in body.newest_text


@pytest.mark.unit
@pytest.mark.parametrize("quote", [
    '<div class="gmail_quote"><div class="gmail_attr">On Mon, Sam wrote:</div><blockquote class="gmail_quote">',
    '<blockquote type="cite">',
    '<div id="x_divRplyFwdMsg">',
    "<p>On Mon, Oct 5, 2026 at 9:00 AM Sam Roe &lt;sam@example.org&gt; wrote:</p><div>",
    "<p>---------- Forwarded message ---------</p><div>",
])
def test_parse_html_body_quote_markers(quote):
    html = (f'<p>See the attached file.</p><p>Thanks,</p><p><a href="{SIGNATURE_LINK}">signature</a></p><p>Pat</p>'
            f'{quote}<p>see <a href="{EARLIER}">this</a></p></div>')

    anchors = parse_html_body(html, SETTINGS).anchors

    assert (anchors[SIGNATURE_LINK].signature, anchors[SIGNATURE_LINK].quoted) == (True, False)
    assert (anchors[EARLIER].signature, anchors[EARLIER].quoted) == (False, True)


@pytest.mark.unit
def test_parse_html_body_link_text_is_never_a_sign_off():
    anchors = parse_html_body(f'<p><a href="{LURE}">Thanks!</a></p><p><a href="{EARLIER}">On it</a></p>',
                              SETTINGS).anchors

    assert not anchors[EARLIER].signature


@pytest.mark.unit
@pytest.mark.parametrize("html", [
    # an inline tag does not make its text a line of its own
    f'<p>Hello,</p><p><b>Thank you</b> for your payment. <a href="{LURE}">View invoice</a></p>',
    f'<p>Hello,</p><p><span>Best</span> offers this week: <a href="{LURE}">Shop</a></p>',
    # a heading that thanks the recipient before anything else is not a sign-off
    f'<h2>Thank you!</h2><p><a href="{LURE}">View invoice</a></p>',
    # nor is one that prose follows
    (f'<p>Hello,</p><h2>Thank you!</h2><p>Your payment of $500 was received today and your receipt is ready to '
     f'view. <a href="{LURE}">View invoice</a></p>'),
    # nor is a sign-off inside a table cell's text
    f'<table><tr><td>Hello, <b>Thanks</b>, your order shipped</td><td><a href="{LURE}">Track</a></td></tr></table>',
    # a button's text does not decide a sign-off, and nothing after it does either
    f'<p>Dear customer,</p><h2>Thank you!</h2><p><a href="{LURE}">View invoice</a></p>',
    f'<p><a href="https://www.example.com/web">View in browser</a></p><h2>Thank you!</h2><p><a href="{LURE}">View invoice</a></p>',
    # the sentence below the button does
    (f'<p>Dear customer,</p><h2>Thank you!</h2><p><a href="{LURE}">View invoice</a></p>'
     f'<p>Your payment of $500 was received today and your receipt is ready to view.</p>'),
])
def test_parse_html_body_thanks_is_not_always_a_sign_off(html):
    body = parse_html_body(html, LureURLSettings())

    assert body.anchors[LURE].signature is False


@pytest.mark.unit
def test_parse_html_body_signature_after_a_logo_link():
    # a signature's first line can be a linked logo with no text
    html = (f'<p>See the attached file.</p><p>Regards,</p><p><a href="{EARLIER_SIGNATURE}"><img src="logo.png"></a></p>'
            f'<p><a href="{SIGNATURE_LINK}">www.estimating.example.org</a></p>')

    anchors = parse_html_body(html, SETTINGS).anchors

    assert anchors[EARLIER_SIGNATURE].signature is True
    assert anchors[SIGNATURE_LINK].signature is True


@pytest.mark.unit
def test_parse_html_body_link_lines_are_decided_with_their_sign_off():
    # the name line below decides the sign-off, and the link line between is part of the signature
    html = (f'<p>See the attached file.</p><p>Thanks,</p><p><a href="{SIGNATURE_LINK}">www.estimating.example.org</a></p>'
            f'<p>Pat Doe</p>')

    assert parse_html_body(html, SETTINGS).anchors[SIGNATURE_LINK].signature is True


@pytest.mark.unit
def test_parse_html_body_signature_link_text_is_not_the_message():
    # the link's text is the signature's once the name line decides it, so it refers to no attachment
    html = ('<p>Please review the bid.</p><p>Thanks,</p><p><a href="https://www.example.org/terms">See the attached '
            'terms</a></p><p>Pat Doe</p>')

    body = parse_html_body(html, LureURLSettings())

    assert body.newest_text == "Please review the bid.\nThanks,"
    assert find_phrase(LureURLSettings().attachment_reference_keywords, body.newest_text) is None


@pytest.mark.unit
def test_parse_html_body_quoted_message_does_not_decide_a_sign_off():
    # the earlier message's own signature is no answer to the newest message's "Thank you!"
    html = (f'<p>Dear customer,</p><h2>Thank you!</h2><p><a href="{LURE}">View invoice</a></p>'
            f'<div id="divRplyFwdMsg"><p>From: Sam</p></div><p>Can you send it?</p><p>Regards,</p><p>Sam Roe</p>')

    anchors = parse_html_body(html, LureURLSettings()).anchors

    assert (anchors[LURE].signature, anchors[LURE].quoted) == (False, False)


@pytest.mark.unit
def test_parse_html_body_head_is_not_a_line():
    # the title would be the first line, and the heading a sign-off after it
    html = (f'<html><head><title>Invoice</title><style>p {{ color: red; }}</style></head><body>'
            f'<script>var x = 1;</script><h2>Thank you!</h2><p><a href="{LURE}">View invoice</a></p></body></html>')

    body = parse_html_body(html, LureURLSettings())

    assert body.anchors[LURE].signature is False
    assert body.newest_text == "Thank you!\nView invoice"


@pytest.mark.unit
def test_parse_html_body_sentence_settings():
    html = (f'<p>Hello,</p><h2>Thank you!</h2><p>Your receipt is ready.</p><p><a href="{LURE}">View invoice</a></p>')

    # four words are not a sentence by default, so the heading is a sign-off
    assert parse_html_body(html, LureURLSettings()).anchors[LURE].signature is True
    assert parse_html_body(html, LureURLSettings(sentence_end_words=4)).anchors[LURE].signature is False
    assert parse_html_body(html, LureURLSettings(sentence_words=3)).anchors[LURE].signature is False


@pytest.mark.unit
def test_parse_html_body_newest_text_stops_at_the_signature():
    html = ("<p>Your account needs attention. <a href='https://evil.example.net/'>Verify</a></p><p>Regards,<br>Pat</p>"
            "<p>This e-mail and any files attached to it are confidential and intended only for its addressee.</p>")

    body = parse_html_body(html, SETTINGS)

    assert "confidential" not in body.newest_text
    assert find_phrase(LureURLSettings().attachment_reference_keywords, body.newest_text) is None


@pytest.mark.unit
def test_parse_text_body_thanks_first_line_is_not_a_sign_off():
    body = parse_text_body(f"Thank you!\nView your invoice: {LURE}\n", LureURLSettings())

    assert body.text_urls[LURE] == (False, False)


@pytest.mark.unit
def test_parse_text_body_url_lines_are_decided_with_their_sign_off():
    # a line of URLs only does not decide a sign-off; a name line after it does
    settings = LureURLSettings()
    assert parse_text_body(f"Dear customer,\nThank you!\n{LURE}\n", settings).text_urls[LURE] == (False, False)
    assert parse_text_body(f"See the attached file.\nThanks,\n{SIGNATURE_LINK}\nPat Doe\n",
                           settings).text_urls[SIGNATURE_LINK] == (True, False)


@pytest.mark.unit
@pytest.mark.parametrize("html", [
    f'<p>From: IT Service Desk</p><p>You have a new voicemail. <a href="{LURE}">Listen</a></p>',
    f'<table><tr><td>From:</td><td>IT Service Desk</td></tr><tr><td>Date:</td><td>Monday</td></tr></table>'
    f'<p>You have a new voicemail. <a href="{LURE}">Listen</a></p>',
])
def test_parse_html_body_a_from_line_alone_starts_no_message(html):
    body = parse_html_body(html, SETTINGS)

    assert body.anchors[LURE].quoted is False
    assert "You have a new voicemail." in body.newest_text


@pytest.mark.unit
def test_parse_text_body_reply_header_starts_an_earlier_message():
    text = f"Please see the attached bid.\n\nFrom: Sam Roe\nSent: Monday\nTo: Pat Doe\nSubject: bid\nHere is {EARLIER}\n"

    body = parse_text_body(text, SETTINGS)

    assert body.text_urls[EARLIER] == (False, True)
    # the header is the earlier message's
    assert body.newest_text == "Please see the attached bid."


@pytest.mark.unit
def test_parse_html_body_ignores_comments():
    # Outlook's conditional comments, with a reply header inside, are never shown
    html = (f'<!--[if mso]><p>From: x</p><p>Sent: y</p><p>To: z</p><![endif]--><p>See the attached file.</p>'
            f'<p><a href="{LURE}">View</a></p>')

    body = parse_html_body(html, SETTINGS)

    assert (body.anchors[LURE].signature, body.anchors[LURE].quoted) == (False, False)
    assert body.newest_text == "See the attached file.\nView"


@pytest.mark.unit
def test_parse_html_body_deep_nesting():
    html = "<div>" * 5000 + f'<a href="{LURE}">View</a>' + "</div>" * 5000

    assert parse_html_body(html, SETTINGS).anchors[LURE].text == "View"


@pytest.mark.unit
def test_parse_text_body_thread():
    text = f"""Please review the attached bid documents.
> {LURE}

Respectfully,
Pat Doe
<{SIGNATURE_LINK}>

-----Original Message-----
From: Sam Roe
Here is {EARLIER}.
"""

    body = parse_text_body(text, SETTINGS)

    # a line quoted with ">" is an earlier message's, even inside the newest one
    assert body.text_urls[LURE] == (False, True)
    assert body.text_urls[SIGNATURE_LINK] == (True, False)
    assert body.text_urls[EARLIER] == (False, True)
    assert body.newest_text.startswith("Please review the attached bid documents.")
    assert LURE not in body.newest_text
    assert "Here is" not in body.newest_text


@pytest.mark.unit
@pytest.mark.parametrize("line, expected", [
    ("Respectfully,", True),
    ("Thanks, Sam", True),
    ("Best", True),
    ("Kind regards.", True),
    ("Thanks - Sam", True),
    ("Thanks for the bid", False),
    ("Best-in-class pricing", False),
    ("Regards," + " x" * 50, False),
])
def test_is_sign_off(line, expected):
    assert is_sign_off(line, LureURLSettings().sign_off_phrases) is expected


@pytest.mark.unit
def test_phrase_around():
    text = "Hi\nPlease review the attached bid documents.\nThanks"
    match = find_phrase(["attached"], text)
    assert phrase_around(text, match.start(), match.end()) == "Please review the attached bid documents."
    # whole words only, within the width
    text = "x" * 10 + " one two three attached four five six " + "y" * 10
    match = find_phrase(["attached"], text)
    assert phrase_around(text, match.start(), match.end(), width=15) == "one two three attached four five six"


@pytest.mark.unit
def test_find_phrase():
    phrases = LureURLSettings().attachment_reference_keywords

    # the first one in the text, so the longer phrase wins where it is there
    assert find_phrase(phrases, "Please find attached the bid.").group(0) == "Please find attached"
    assert find_phrase(phrases, "The bid is attached.").group(0) == "attached"
    assert find_phrase(phrases, "Please SEE ATTACHMENT for details").group(0) == "SEE ATTACHMENT"
    # the first one in the text, whichever phrase it is
    assert find_phrase(phrases, "enclosed is the form, see attachment").start() == 0
    # a banner or disclaimer on most mail
    assert find_phrase(phrases, "CAUTION: Do not click links or open attachments unless you know the sender.") is None
    assert find_phrase(phrases, "This e-mail and any attachments are confidential.") is None
    assert find_phrase(phrases, "unattached") is None
    assert find_phrase([""], "anything") is None


#
# scoring
#

def _candidate(root, url, sources, **kwargs) -> Candidate:
    return Candidate(observable=root.add_observable_by_spec(F_URL, url), sources=set(sources), **kwargs)


@pytest.mark.unit
def test_score_candidates_prefers_the_call_to_action():
    root = RootAnalysis()
    lure_candidate = _candidate(root, LURE, [SOURCE_BODY], in_parsed_body=True,
                                anchor=Anchor("Review Document", True))
    privacy = _candidate(root, PRIVACY, [SOURCE_BODY], in_parsed_body=True, anchor=Anchor("Privacy", False))
    logo = _candidate(root, LOGO, [SOURCE_BODY], in_parsed_body=True)

    score_candidates([lure_candidate, privacy, logo], {"example.com"}, SETTINGS)

    assert lure_candidate.reasons == [
        "found in the email body",
        "clickable link with text 'Review Document'",
        "styled as a button",
        "call-to-action text (review)",
        "the only linked external domain",
    ]
    assert lure_candidate.score == 90
    assert privacy.score < 0
    assert "looks like a footer link (privacy)" in privacy.reasons
    assert "same domain as the sender (example.com)" in privacy.reasons
    assert logo.score < privacy.score
    assert "points at an image or static resource" in logo.reasons
    assert "not a clickable link in the body" in logo.reasons


@pytest.mark.unit
def test_score_candidates_uses_the_settings_weights():
    # a distinct power of two per weight, so a score says exactly which weights were applied, and no two weights
    # fire on the same set of candidates, so two weights trading places changes some score
    settings = LureURLSettings(
        call_to_action_keywords=["review"], noise_keywords=["unsubscribe"], benign_domains=["fonts.googleapis.com"],
        weights={"qr": 1, "body": 2, "attachment": 4, "clickable": 8, "button": 16, "call_to_action": 32,
                 "only_domain": 64, "unwrapped": 128, "detection": 256, "not_a_link": 512, "sender_domain": 1024,
                 "noise": 2048, "static": 4096, "benign": 8192})
    root = RootAnalysis()
    wrapper = "https://nam01.safelinks.protection.outlook.com/?url=x"
    lure_candidate = _candidate(root, LURE, [SOURCE_BODY], in_parsed_body=True, anchor=Anchor("Review Document", True),
                                wrapped_by=wrapper)
    lure_candidate.observable.add_detection_point("known bad")
    plain_cta = _candidate(root, "https://f.example.org/x", [SOURCE_BODY], in_parsed_body=True,
                           anchor=Anchor("Review", False))
    flagged_button = _candidate(root, "https://g.example.info/x", [SOURCE_BODY], in_parsed_body=True,
                                anchor=Anchor("Open", True))
    flagged_button.observable.add_detection_point("known bad")
    plain_text_link = _candidate(root, "https://www.example.com/j", [SOURCE_BODY], wrapped_by=wrapper)
    plain_text_link.observable.add_detection_point("known bad")
    qr = _candidate(root, "https://qr.example.com/a", [SOURCE_QR], in_parsed_body=True)
    logo = _candidate(root, "https://www.example.com/logo.png", [SOURCE_BODY], in_parsed_body=True)
    pixel = _candidate(root, "https://www.example.com/pixel", [SOURCE_BODY], in_parsed_body=True)
    footer = _candidate(root, "https://www.example.com/unsubscribe", [SOURCE_ATTACHMENT],
                        attachments=["statement.pdf"], pdf_link=True)
    font = _candidate(root, "https://fonts.googleapis.com/css", [SOURCE_ATTACHMENT], attachments=["page.html"])

    # one at a time: only_domain depends on which other links are scored with a candidate
    for candidate in (lure_candidate, plain_cta, flagged_button, plain_text_link, qr, logo, pixel, footer, font):
        score_candidates([candidate], {"example.com"}, settings)

    # body + clickable + button + call_to_action + only_domain + unwrapped + detection
    assert lure_candidate.score == 506
    # body + clickable + call_to_action + only_domain
    assert plain_cta.score == 106
    # body + clickable + button + only_domain + detection
    assert flagged_button.score == 346
    # body + unwrapped + detection + sender_domain
    assert plain_text_link.score == 1410
    # qr + sender_domain
    assert qr.score == 1025
    # body + not_a_link + sender_domain + static
    assert logo.score == 5634
    # body + not_a_link + sender_domain
    assert pixel.score == 1538
    # attachment + clickable (a PDF link) + sender_domain + noise
    assert footer.score == 3084
    # attachment + benign
    assert font.score == 8196


@pytest.mark.unit
def test_score_candidates_other_signals():
    root = RootAnalysis()
    qr = _candidate(root, "https://qr.example.net/a", [SOURCE_QR], in_parsed_body=True)
    attached = _candidate(root, "https://attached.example.org/b", [SOURCE_ATTACHMENT], attachments=["statement.html"])
    wrapped = _candidate(root, "https://wrapped.example.info/c", [SOURCE_BODY],
                         wrapped_by="https://nam01.safelinks.protection.outlook.com/?url=x")
    wrapped.observable.add_detection_point("known bad")
    benign = _candidate(root, "https://fonts.googleapis.com/css", [SOURCE_BODY])

    score_candidates([qr, attached, wrapped, benign], set(), SETTINGS)

    # a QR code in an image is never a link in the body
    assert qr.reasons == ["decoded from a QR code"]
    assert attached.reasons == ["found in attachment statement.html"]
    assert "unwrapped from nam01.safelinks.protection.outlook.com/?url=x" in wrapped.reasons
    assert "has detection points" in wrapped.reasons
    assert "benign infrastructure domain" in benign.reasons
    assert benign.score < 0


@pytest.mark.unit
def test_score_candidates_pdf_link_carrying_urls():
    root = RootAnalysis()
    tracker = _candidate(root, TRACKER, [SOURCE_ATTACHMENT], attachments=["statement.pdf"], pdf_link=True,
                         carries=["https://evil.example.net/login", "https://decoy.example.org/home"])

    score_candidates([tracker], set(), SETTINGS)

    assert tracker.reasons == [
        "found in attachment statement.pdf",
        "clickable link in a PDF",
        "carries 2 URLs: evil.example.net/login, decoy.example.org/home",
        "the only linked external domain",
    ]
    assert tracker.score == 50
    assert tracker.highlights == [
        ["statement.pdf"],
        [],
        ["evil.example.net/login", "decoy.example.org/home"],
        [],
    ]


BID_PORTAL = "https://bids.example.net/portal/login"
CONTRACTOR = "https://www.contractor.example.com"


@pytest.mark.unit
def test_score_candidates_pdf_link_beats_a_signature_link():
    # the body asks for the attachment and signs off above a link; the PDF has two links, and its text says which
    # one is the lure
    root = RootAnalysis()
    signature = _candidate(root, SIGNATURE_LINK, [SOURCE_BODY], in_parsed_body=True,
                           anchor=Anchor("signature", False, signature=True), signature=True)
    portal = _candidate(root, BID_PORTAL, [SOURCE_ATTACHMENT], attachments=["bid.pdf"], pdf_link=True,
                        anchor=Anchor("View Bid Documents", False, position=0, pdf=True), pdf_name="bid.pdf",
                        pdf_link_count=2)
    contractor = _candidate(root, CONTRACTOR, [SOURCE_ATTACHMENT], attachments=["bid.pdf"], pdf_link=True,
                            anchor=Anchor("www.contractor.example.com", False, position=1, pdf=True),
                            pdf_name="bid.pdf", pdf_link_count=2)

    score_candidates([signature, portal, contractor], set(), LureURLSettings(),
                     "Hi all,\nPlease review the attached bid documents and confirm by Friday.\nRespectfully,")

    assert portal.reasons == [
        "found in attachment bid.pdf",
        "the email refers to its attachment: 'Please review the attached bid documents and confirm by Friday.'",
        "clickable link in a PDF with text 'View Bid Documents'",
        "call-to-action text (view)",
    ]
    assert portal.highlights[1] == ["Please review the attached bid documents and confirm by Friday."]
    # body + clickable + call_to_action ("sign" in "signature") + signature_block
    assert "in a signature block" in signature.reasons
    assert signature.score == 40
    assert contractor.score == 60
    assert portal.score == 80
    assert sorted([signature, contractor, portal], key=lambda c: c.rank_key) == [portal, contractor, signature]


@pytest.mark.unit
def test_score_candidates_context_signals_use_their_weights():
    settings = LureURLSettings(
        call_to_action_keywords=[], noise_keywords=[], benign_domains=[],
        weights={"qr": 0, "body": 0, "attachment": 0, "clickable": 0, "only_domain": 0, "attachment_reference": 1,
                 "only_link": 2, "signature_block": 4, "quoted_message": 8})
    root = RootAnalysis()
    only_link = _candidate(root, "https://a.example.net/", [SOURCE_ATTACHMENT], attachments=["one.pdf"],
                           pdf_link=True, pdf_name="one.pdf", pdf_link_count=1)
    quoted_signature = _candidate(root, "https://b.example.org/", [SOURCE_BODY], signature=True, quoted=True)
    in_body_and_attachment = _candidate(root, "https://c.example.com/", [SOURCE_BODY, SOURCE_ATTACHMENT],
                                        attachments=["two.pdf"])

    score_candidates([only_link, quoted_signature, in_body_and_attachment], set(), settings,
                     "the documents are enclosed")

    # attachment_reference + only_link
    assert only_link.score == 3
    assert "the only link in one.pdf" in only_link.reasons
    # signature_block + quoted_message
    assert quoted_signature.score == 12
    assert "in an earlier message the email quotes" in quoted_signature.reasons
    # a link the body has itself is scored as a body link
    assert in_body_and_attachment.score == 0


@pytest.mark.unit
def test_score_candidates_no_attachment_reference():
    root = RootAnalysis()
    attached = _candidate(root, "https://attached.example.org/b", [SOURCE_ATTACHMENT], attachments=["statement.html"])

    score_candidates([attached], set(), LureURLSettings(), "Your statement is ready.")

    assert not any(r.startswith("the email refers to its attachment") for r in attached.reasons)


@pytest.mark.unit
def test_highlights_link_text():
    root = RootAnalysis()
    candidate = _candidate(root, LURE, [SOURCE_BODY], in_parsed_body=True, anchor=Anchor("Review Document", True))

    score_candidates([candidate], set(), SETTINGS)

    assert candidate.highlights[candidate.reasons.index("clickable link with text 'Review Document'")] == [
        "Review Document"]
    assert len(candidate.highlights) == len(candidate.reasons)


@pytest.mark.unit
def test_reason_segments():
    assert reason_segments("carries 2 URLs: a.example.com/x, b.example.com/y", ["a.example.com/x", "b.example.com/y"]) == [
        ("carries 2 URLs: ", False), ("a.example.com/x", True), (", ", False), ("b.example.com/y", True)]
    assert reason_segments("found in attachment x.pdf", ["x.pdf"]) == [("found in attachment ", False), ("x.pdf", True)]
    # a value that is not in the reason, or empty, is skipped
    assert reason_segments("styled as a button", ["nope", ""]) == [("styled as a button", False)]
    assert reason_segments("plain", []) == [("plain", False)]


@pytest.mark.unit
@pytest.mark.parametrize("value, expected", [
    ("https://evil.example.net/login", True),
    ("HTTP://evil.example.net/", True),
    ("mailto:user@example.com", False),
    # urlparse raises on this, and an attacker writes the link
    ("http://[x/", False),
])
def test_is_http_url(value, expected):
    assert is_http_url(value) is expected


@pytest.mark.unit
def test_only_external_domain_counts_links_only():
    root = RootAnalysis()
    lure_candidate = _candidate(root, LURE, [SOURCE_BODY], in_parsed_body=True, anchor=Anchor("Review", False))
    # the logo comes from a CDN, which is not a link the recipient follows
    cdn_logo = _candidate(root, "https://cdn.example.org/logo.png", [SOURCE_BODY], in_parsed_body=True)

    score_candidates([lure_candidate, cdn_logo], set(), SETTINGS)

    assert "the only linked external domain" in lure_candidate.reasons


@pytest.mark.unit
def test_carried_urls():
    assert carried_urls(TRACKER) == ["https://evil.example.net/login", "https://decoy.example.org/home"]
    assert carried_urls("https://example.com/?q=hello&next=/relative") == []
    assert carried_urls("http://[::1") == []


@pytest.mark.unit
def test_fold_carried_urls():
    root = RootAnalysis()
    tracker = _candidate(root, TRACKER, [SOURCE_BODY], anchor=Anchor("View", False))
    evil = _candidate(root, "https://evil.example.net/login", [SOURCE_BODY])
    decoy = _candidate(root, "https://decoy.example.org/home", [SOURCE_BODY])
    other = _candidate(root, "https://other.example.com/", [SOURCE_BODY])

    # the link in the email is the tracker; what it carries is part of it
    assert fold_carried_urls([evil, tracker, decoy, other]) == [tracker, other]
    assert tracker.carries == ["https://evil.example.net/login", "https://decoy.example.org/home"]


@pytest.mark.unit
def test_fold_carried_urls_chain():
    root = RootAnalysis()
    lure_url = "https://evil.example.net/login"
    inner = "https://inner.example.org/r?to=https%3A%2F%2Fevil.example.net%2Flogin"
    outer = "https://outer.example.com/c?u=https%3A%2F%2Finner.example.org%2Fr%3Fto%3Dhttps%253A%252F%252Fevil.example.net%252Flogin"
    for order in ([outer, inner, lure_url], [lure_url, inner, outer]):
        candidates = [_candidate(root, url, [SOURCE_BODY]) for url in order]

        # only the link the recipient clicks is left, whichever order the URLs came in
        [remaining] = fold_carried_urls(candidates)
        assert remaining.observable.value == outer
        assert remaining.carries == [inner]


@pytest.mark.unit
def test_rank_key_is_stable():
    root = RootAnalysis()
    first = _candidate(root, "https://z.example.com/", [SOURCE_BODY], anchor=Anchor("one", False, position=0))
    second = _candidate(root, "https://a.example.com/", [SOURCE_BODY], anchor=Anchor("two", False, position=2))
    no_anchor_z = _candidate(root, "https://z.example.net/", [SOURCE_BODY])
    no_anchor_a = _candidate(root, "https://a.example.net/", [SOURCE_BODY])

    # equal scores: by position in the body, then by value, never by the order they came in
    ranked = sorted([no_anchor_z, second, no_anchor_a, first], key=lambda c: c.rank_key)
    assert ranked == [first, second, no_anchor_a, no_anchor_z]


@pytest.mark.unit
def test_rank_key_body_link_before_pdf_link():
    root = RootAnalysis()
    body_link = _candidate(root, "https://z.example.com/", [SOURCE_BODY], anchor=Anchor("body", False, position=3))
    pdf_first = _candidate(root, "https://a.example.com/", [SOURCE_ATTACHMENT],
                           anchor=Anchor("pdf", False, position=0, pdf=True))
    pdf_second = _candidate(root, "https://b.example.com/", [SOURCE_ATTACHMENT],
                            anchor=Anchor("pdf", False, position=1, pdf=True))
    no_anchor = _candidate(root, "https://0.example.com/", [SOURCE_BODY])

    # a PDF's link positions are not body positions: link 0 of a PDF does not come before link 3 of the body
    ranked = sorted([no_anchor, pdf_second, pdf_first, body_link], key=lambda c: c.rank_key)
    assert ranked == [body_link, pdf_first, pdf_second, no_anchor]


@pytest.mark.unit
def test_sender_domains():
    analysis = EmailAnalysis()
    analysis.email = {"from_address": "Billing <billing@mail.sender.example.com>", "return_path": "<bounce@bounces.example.org>"}
    assert sender_domains(analysis) == {"example.com", "example.org"}

    assert sender_domains(EmailAnalysis()) == set()


#
# candidate collection over a tree built by hand
#

def _file(analysis, tmp_path: Path, name: str, content: str = "x"):
    path = tmp_path / name
    path.write_text(content)
    return analysis.add_file_observable(str(path))


def _extracted(file_observable, *urls):
    analysis = URLExtractionAnalysis()
    file_observable.add_analysis(analysis)
    return [analysis.add_observable_by_spec(F_URL, url) for url in urls]


def _email_tree(root_analysis, tmp_path, html=None):
    email_file = _file(root_analysis, tmp_path, "message.email.rfc822", "From: x")
    email_analysis = EmailAnalysis()
    email_file.add_analysis(email_analysis)
    body = None
    if html is not None:
        body = _file(email_analysis, tmp_path, "message.email.rfc822.unknown_text_html_000.html", html)
    return email_file, email_analysis, body


@pytest.mark.integration
def test_collector_sources(root_analysis, tmp_path):
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, LURE_HTML)
    _extracted(body, LURE, LOGO)

    # a QR code in an inline image
    image = _file(email_analysis, tmp_path, "image001.png", "png")
    qr = QRCodeAnalysis()
    image.add_analysis(qr)
    qr_text = _file(qr, tmp_path, "image001.png.qrcode", "https://qr.example.net/a\n")
    _extracted(qr_text, "https://qr.example.net/a")

    # a link in an attachment
    attachment = _file(email_analysis, tmp_path, "statement.html", "<a href='https://attached.example.org/b'>b</a>")
    _extracted(attachment, "https://attached.example.org/b")

    # what a crawl found after the click is not part of the lure
    crawl = PhishkitAnalysis()
    body.add_analysis(crawl)
    crawl.add_observable_by_spec(F_URL, "https://after.example.net/the-click")

    collector = CandidateCollector()
    candidates = {c.observable.value: c for c in collector.collect(email_analysis)}

    assert set(candidates) == {LURE, LOGO, "https://qr.example.net/a", "https://attached.example.org/b"}
    assert candidates[LURE].sources == {SOURCE_BODY}
    assert candidates[LURE].anchor == Anchor("Review Document", True)
    assert candidates[LOGO].in_parsed_body and candidates[LOGO].anchor is None
    assert candidates["https://qr.example.net/a"].sources == {SOURCE_QR}
    assert candidates["https://attached.example.org/b"].sources == {SOURCE_ATTACHMENT}
    assert candidates["https://attached.example.org/b"].attachments == ["statement.html"]
    assert collector.has_inner_email is False


@pytest.mark.integration
def test_collector_pdf_link_carrying_urls(root_analysis, tmp_path):
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, "<p>see the attached statement</p>")
    pdf = _file(email_analysis, tmp_path, "statement.pdf", "%PDF-1.4")
    pdf_analysis = PDFAnalysis()
    pdf.add_analysis(pdf_analysis)
    # the PDF's link annotation is the tracker; urlfinderlib also extracts what it carries
    annotations = _file(pdf_analysis, tmp_path, "statement.pdf.annotation_uris.txt", TRACKER)
    annotations.add_yara_meta("type", "document.pdf.annotation_uris")
    _extracted(annotations, TRACKER, "https://evil.example.net/login", "https://decoy.example.org/home")
    # the same URLs found again in the PDF's raw objects are not links
    objects = _file(pdf_analysis, tmp_path, "statement.pdf.pdfparser", "objects " + TRACKER)
    _extracted(objects, TRACKER, "http://www.example.com/ns/metadata")

    candidates = {c.observable.value: c for c in CandidateCollector().collect(email_analysis)}

    # what the tracker carries is folded into it: the tracker is the link in the PDF
    assert set(candidates) == {TRACKER, "http://www.example.com/ns/metadata"}
    tracker = candidates[TRACKER]
    assert tracker.pdf_link is True
    assert tracker.carries == ["https://evil.example.net/login", "https://decoy.example.org/home"]
    assert tracker.attachments == ["statement.pdf"]
    assert candidates["http://www.example.com/ns/metadata"].pdf_link is False

    score_candidates(list(candidates.values()), set(), SETTINGS)
    assert tracker.score > candidates["http://www.example.com/ns/metadata"].score


@pytest.mark.integration
def test_collector_pdf_link_text(root_analysis, tmp_path):
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, "<p>see the attached bid</p>")
    pdf = _file(email_analysis, tmp_path, "bid.pdf", "%PDF-1.4")
    pdf_analysis = PDFAnalysis()
    pdf.add_analysis(pdf_analysis)
    link_text = PDFLinkTextAnalysis()
    pdf.add_analysis(link_text)
    link_text.details = {"links": [
        {"url": BID_PORTAL, "page": 1, "text": "View Bid Documents", "line": "Bids: View Bid Documents"},
        # nothing under the link: the line it is on is the best there is
        {"url": CONTRACTOR, "page": 2, "text": None, "line": "Visit www.contractor.example.com"},
    ]}
    annotations = _file(pdf_analysis, tmp_path, "bid.pdf.annotation_uris.txt", f"{BID_PORTAL}\n{CONTRACTOR}")
    annotations.add_yara_meta("type", "document.pdf.annotation_uris")
    _extracted(annotations, BID_PORTAL, CONTRACTOR)

    collector = CandidateCollector(root_analysis.uuid)
    candidates = {c.observable.value: c for c in collector.collect(email_analysis)}

    portal = candidates[BID_PORTAL]
    assert portal.anchor == Anchor("View Bid Documents", False, position=0, pdf=True)
    assert (portal.pdf_name, portal.pdf_link_count) == ("bid.pdf", 2)
    assert candidates[CONTRACTOR].anchor.text == "Visit www.contractor.example.com"
    assert collector.body_text == "see the attached bid"


@pytest.mark.integration
def test_collector_pdf_link_text_after_a_reload(root_analysis, tmp_path):
    # the lure's crawl delays the alert's analysis, so its later final passes read the tree back from disk
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, "<p>see the attached bid</p>")
    pdf = _file(email_analysis, tmp_path, "bid.pdf", "%PDF-1.4")
    pdf_analysis = PDFAnalysis()
    pdf.add_analysis(pdf_analysis)
    link_text = PDFLinkTextAnalysis()
    pdf.add_analysis(link_text)
    link_text.details = {"links": [{"url": BID_PORTAL, "page": 1, "text": "View Bid Documents", "line": None}]}
    annotations = _file(pdf_analysis, tmp_path, "bid.pdf.annotation_uris.txt", BID_PORTAL)
    annotations.add_yara_meta("type", "document.pdf.annotation_uris")
    _extracted(annotations, BID_PORTAL)
    root_analysis.save()

    root = load_root(get_storage_dir(root_analysis.uuid))
    reloaded = root.get_observable(email_file.uuid).get_and_load_analysis(EmailAnalysis)
    [portal] = CandidateCollector(root.uuid).collect(reloaded)

    assert portal.anchor == Anchor("View Bid Documents", False, position=0, pdf=True)


@pytest.mark.integration
def test_collector_pdf_analysis_without_links(root_analysis, tmp_path):
    # an alert whose PDF has no link text analysis: pdf_link_text is disabled, or could not read the PDF
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, "<p>see the attached bid</p>")
    pdf = _file(email_analysis, tmp_path, "bid.pdf", "%PDF-1.4")
    pdf_analysis = PDFAnalysis()
    pdf.add_analysis(pdf_analysis)
    annotations = _file(pdf_analysis, tmp_path, "bid.pdf.annotation_uris.txt", BID_PORTAL)
    annotations.add_yara_meta("type", "document.pdf.annotation_uris")
    _extracted(annotations, BID_PORTAL)

    [portal] = CandidateCollector().collect(email_analysis)

    assert portal.pdf_link is True
    assert portal.anchor is None and portal.pdf_name is None
    score_candidates([portal], set(), SETTINGS)
    assert "clickable link in a PDF" in portal.reasons


@pytest.mark.integration
def test_collector_signature_blocks(root_analysis, tmp_path):
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, THREAD_HTML)
    _extracted(body, SIGNATURE_LINK, EARLIER, EARLIER_SIGNATURE)
    # the plain text alternative of the same thread, with a URL the HTML part has only as an image
    text = _file(email_analysis, tmp_path, "message.email.rfc822.unknown_text_plain_000.txt",
                 f"Please review the attached bid documents.\nRespectfully,\nPat\n{LOGO}\n")
    _extracted(text, LOGO)

    collector = CandidateCollector(root_analysis.uuid)
    candidates = {c.observable.value: c for c in collector.collect(email_analysis)}

    assert (candidates[SIGNATURE_LINK].signature, candidates[SIGNATURE_LINK].quoted) == (True, False)
    assert (candidates[EARLIER].signature, candidates[EARLIER].quoted) == (False, True)
    assert (candidates[EARLIER_SIGNATURE].signature, candidates[EARLIER_SIGNATURE].quoted) == (True, True)
    assert candidates[LOGO].signature is True
    assert "Please review the attached bid documents and confirm by Friday." in collector.body_text
    assert "Here is the" not in collector.body_text


@pytest.mark.integration
def test_collector_skips_inner_email(root_analysis, tmp_path):
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, "<p>see attached</p>")
    inner = _file(email_analysis, tmp_path, "message.email.rfc822.email.rfc822", "From: y")
    inner_analysis = EmailAnalysis()
    inner.add_analysis(inner_analysis)
    inner_body = _file(inner_analysis, tmp_path, "inner.email.rfc822.unknown_text_html_000.html", LURE_HTML)
    _extracted(inner_body, LURE)
    # EmailAnalyzer extracts the inner email's parts into the outer email too
    outer_copy = _file(email_analysis, tmp_path, "message.email.rfc822.unknown_text_html_001.html", LURE_HTML)
    _extracted(outer_copy, LURE)

    collector = CandidateCollector()

    assert collector.collect(email_analysis) == []
    assert collector.has_inner_email is True


@pytest.mark.integration
def test_collector_unparseable_body(root_analysis, tmp_path, monkeypatch, caplog):
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, LURE_HTML)
    _extracted(body, LURE)

    def _fail(html, sign_offs):
        raise ValueError("bad markup")

    monkeypatch.setattr(lure, "parse_html_body", _fail)
    with caplog.at_level(logging.WARNING):
        [candidate] = CandidateCollector(root_analysis.uuid).collect(email_analysis)

    # the URL is still a candidate, only without its anchor
    assert candidate.observable.value == LURE
    assert candidate.anchor is None
    assert not candidate.in_parsed_body
    [record] = [r for r in caplog.records if "unable to parse email body" in r.getMessage()]
    assert record.levelno == logging.ERROR and record.exc_info
    assert record.root_uuid == root_analysis.uuid


@pytest.mark.integration
def test_collector_body_too_large(root_analysis, tmp_path, monkeypatch, caplog):
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, LURE_HTML)
    _extracted(body, LURE)
    monkeypatch.setattr(lure, "MAX_BODY_BYTES", 10)

    with caplog.at_level(logging.INFO):
        [candidate] = CandidateCollector().collect(email_analysis)

    assert candidate.anchor is None
    assert "too large to parse for lure links" in caplog.text


@pytest.mark.integration
def test_collector_missing_body(root_analysis, tmp_path, caplog):
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, LURE_HTML)
    _extracted(body, LURE)
    Path(body.full_path).unlink()

    with caplog.at_level(logging.WARNING):
        [candidate] = CandidateCollector(root_analysis.uuid).collect(email_analysis)

    assert candidate.anchor is None
    [record] = [r for r in caplog.records if "unable to read email body" in r.getMessage()]
    assert record.levelno == logging.ERROR and record.exc_info
    assert record.root_uuid == root_analysis.uuid


def _module(root):
    return AnalysisModuleAdapter(LureURLAnalyzer(
        context=create_test_context(root=root), config=get_analysis_module_config("lure_url_analyzer")))


@pytest.mark.integration
def test_module_skips_a_url_urlparse_rejects(root_analysis, tmp_path):
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, LURE_HTML)
    _extracted(body, "http://[x/", LURE)

    # one malformed link the attacker wrote must not cost the email its lure
    assert _module(root_analysis).execute_final_analysis(email_file) == AnalysisExecutionResult.INCOMPLETE

    analysis = email_file.get_analysis(LureURLAnalysis)
    assert analysis.primary["url"] == LURE
    assert "http://[x/" not in [c["url"] for c in analysis.candidates]


@pytest.mark.integration
def test_module_rescores_when_a_later_final_pass_adds_urls(root_analysis, tmp_path, caplog):
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, "<p>see the attached sheet</p>")
    module = _module(root_analysis)

    # nothing to score yet, and the analysis stays open
    assert module.execute_final_analysis(email_file) == AnalysisExecutionResult.INCOMPLETE
    assert not email_file.get_analysis(LureURLAnalysis)

    # a module that also works in final analysis (xlmdeobfuscator) adds the lure afterwards
    sheet = _file(email_analysis, tmp_path, "invoice.xls", "sheet")
    [lure_url] = _extracted(sheet, LURE)
    with caplog.at_level(logging.INFO):
        assert module.execute_final_analysis(email_file) == AnalysisExecutionResult.INCOMPLETE
        # a pass that changes nothing does not log the lure again
        assert module.execute_final_analysis(email_file) == AnalysisExecutionResult.INCOMPLETE

    analysis = email_file.get_analysis(LureURLAnalysis)
    assert analysis.primary["url"] == LURE
    assert not analysis.completed
    assert lure_url.has_directive(DIRECTIVE_CRAWL)
    assert caplog.text.count(f"is {LURE}") == 1


def _settings_file(tmp_path, monkeypatch, text: str) -> Path:
    path = tmp_path / "lure_url.yaml"
    path.write_text(text)
    monkeypatch.setattr(get_analysis_module_config("lure_url_analyzer"), "config_path", str(path))
    return path


@pytest.mark.integration
def test_module_crawl_primary_off_and_max_candidates(root_analysis, tmp_path, monkeypatch):
    _settings_file(tmp_path, monkeypatch, "crawl_primary: false\nmax_candidates: 2\n")
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, LURE_HTML)
    urls = _extracted(body, LURE, PRIVACY, UNSUBSCRIBE, LOGO)

    _module(root_analysis).execute_final_analysis(email_file)

    analysis = email_file.get_analysis(LureURLAnalysis)
    assert analysis.primary["url"] == LURE
    assert len(analysis.candidates) == 2
    assert not any(url.has_directive(DIRECTIVE_CRAWL) for url in urls)


@pytest.mark.unit
def test_shipped_settings_file_holds_the_builtin_defaults():
    assert get_analysis_module_config("lure_url_analyzer").config_path == "etc/lure_url.yaml"
    settings = load_lure_settings("etc/lure_url.yaml")

    # the file deployments copy into analyst_data must start from the same values ACE uses without it
    assert settings == LureURLSettings()
    assert "fonts.gstatic.com" in settings.benign_domains
    assert settings.weights.qr == 35 and settings.weights.benign == -50
    assert settings.min_primary_score == 1


@pytest.mark.unit
def test_settings_file_keys_left_out_keep_their_defaults(tmp_path):
    path = tmp_path / "lure_url.yaml"
    path.write_text("benign_domains: [example.net]\nnoise_keywords:\nweights:\n  qr: 50\n")

    settings = load_lure_settings(str(path))

    assert settings.benign_domains == ["example.net"]
    assert settings.noise_keywords == []
    assert "invoice" in settings.call_to_action_keywords
    assert settings.weights.qr == 50
    assert settings.weights.body == 20
    assert settings.max_candidates == 5


@pytest.mark.unit
def test_settings_file_blank_weights_keep_their_defaults(tmp_path):
    # an analyst who comments out every weight leaves `weights:` with nothing under it
    path = tmp_path / "lure_url.yaml"
    path.write_text("weights:\n")

    assert load_lure_settings(str(path)).weights == LureURLWeights()


@pytest.mark.unit
@pytest.mark.parametrize("text", [
    "benign_domain: [example.net]\n",
    "weights:\n  qrr: 50\n",
    "max_candidates: 0\n",
    "benign_domains: [\n",
])
def test_settings_file_that_does_not_load(tmp_path, caplog, text):
    path = tmp_path / "lure_url.yaml"
    path.write_text(text)

    assert load_lure_settings(str(path)) is None

    [record] = [r for r in caplog.records if "unable to load lure url settings" in r.getMessage()]
    assert record.levelno == logging.ERROR and record.exc_info
    assert record.path == str(path)


@pytest.mark.integration
def test_module_reloads_the_settings_file_and_keeps_the_last_good_one(root_analysis, tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(get_config().global_settings, "check_watched_files_frequency", 0)
    path = _settings_file(tmp_path, monkeypatch, "min_primary_score: 1000\n")
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, LURE_HTML)
    _extracted(body, LURE, PRIVACY, UNSUBSCRIBE, LOGO)
    module = _module(root_analysis)

    def edit(text: str, mtime: int):
        path.write_text(text)
        # the watcher notices a change by its mtime, which can be unchanged within one tick
        os.utime(path, (mtime, mtime))
        module.wrapped_module.check_watched_files()
        module.execute_final_analysis(email_file)
        return email_file.get_analysis(LureURLAnalysis).primary

    module.execute_final_analysis(email_file)
    assert email_file.get_analysis(LureURLAnalysis).primary is None

    # a bad edit is rejected whole, and the tuning already in effect stays (the defaults would
    # call LURE the primary)
    assert edit("min_primary_score: [\n", 1_000_000) is None
    assert any(r.levelno == logging.ERROR and "unable to load lure url settings" in r.getMessage()
               for r in caplog.records)

    with caplog.at_level(logging.INFO):
        assert edit("min_primary_score: 1\n", 2_000_000)["url"] == LURE
    assert f"loaded lure url settings from {path}" in caplog.text


@pytest.mark.integration
def test_module_missing_settings_file_uses_the_builtin_defaults(root_analysis, tmp_path, monkeypatch, caplog):
    missing = tmp_path / "missing.yaml"
    monkeypatch.setattr(get_analysis_module_config("lure_url_analyzer"), "config_path", str(missing))
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, LURE_HTML)
    [lure_url] = _extracted(body, LURE)

    _module(root_analysis).execute_final_analysis(email_file)

    assert email_file.get_analysis(LureURLAnalysis).primary["url"] == LURE
    assert lure_url.has_directive(DIRECTIVE_CRAWL)
    [record] = [r for r in caplog.records if "does not exist" in r.getMessage()]
    # the traceback is what gets the record an error report
    assert record.levelno == logging.ERROR and record.exc_info
    assert record.path == str(missing)


@pytest.mark.integration
def test_module_blank_config_path_uses_the_builtin_defaults(root_analysis, tmp_path, monkeypatch):
    monkeypatch.setattr(get_analysis_module_config("lure_url_analyzer"), "config_path", "")
    email_file, email_analysis, body = _email_tree(root_analysis, tmp_path, LURE_HTML)
    _extracted(body, LURE)
    module = _module(root_analysis)

    module.execute_final_analysis(email_file)

    assert email_file.get_analysis(LureURLAnalysis).primary["url"] == LURE
    assert module.wrapped_module.watched_files == {}

@pytest.mark.unit
def test_lure_module_runs_only_on_alerts():
    # an email becomes an alert in correlation mode; scoring and crawling every collected email
    # in email mode would detonate the links of benign mail
    assert "lure_url_analyzer" in get_config().get_module_group_config("correlation").modules
    assert "lure_url_analyzer" not in get_config().get_module_group_config("email").modules


@pytest.mark.unit
def test_build_lure_urls_skips_a_broken_entry(caplog):
    root = RootAnalysis()
    email_file = root.add_observable_by_spec(F_URL, "https://placeholder.example.com/")
    analysis = LureURLAnalysis()
    email_file.add_analysis(analysis)
    analysis.primary = {"url": LURE}

    with caplog.at_level(logging.WARNING):
        assert build_lure_urls(root) == []

    [record] = [r for r in caplog.records if "unable to build the lure url entry" in r.getMessage()]
    assert record.levelno == logging.ERROR and record.exc_info
    assert record.root_uuid == root.uuid and record.observable_uuid == email_file.uuid


#
# the engine, on synthetic emails
#

def _message(subject: str, sender: str = SENDER, text: str = "see the html part", html: str = None) -> EmailMessage:
    message = EmailMessage()
    message["From"] = sender
    message["To"] = RECIPIENT
    message["Subject"] = subject
    message["Message-ID"] = f"<{subject.replace(' ', '-')}@example.com>"
    message.set_content(text)
    if html:
        message.add_alternative(html, subtype="html")
    return message


def _analyze(root_analysis, tmp_path: Path, message: EmailMessage, extra_modules=()):
    path = tmp_path / "message.email.rfc822"
    path.write_bytes(bytes(message))
    root_analysis.alert_type = ANALYSIS_TYPE_MAILBOX
    root_analysis.analysis_mode = "test_groups"
    email_observable = root_analysis.add_file_observable(str(path))
    root_analysis.save()
    root_analysis.schedule()

    engine = Engine()
    for module in ("file_type", "email_analyzer", "url_extraction", "lure_url_analyzer") + tuple(extra_modules):
        engine.configuration_manager.enable_module(module, "test_groups")
    engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)

    root = load_root(get_storage_dir(root_analysis.uuid))
    email_observable = root.get_observable(email_observable.uuid)
    return root, email_observable.get_and_load_analysis(LureURLAnalysis)


@pytest.mark.integration
def test_engine_picks_the_button(root_analysis, tmp_path):
    root, analysis = _analyze(root_analysis, tmp_path, _message("shared document", html=LURE_HTML))

    assert analysis.primary["url"] == LURE
    assert "styled as a button" in analysis.primary["reasons"]
    assert analysis.summary.startswith(f"Lure URL Analysis: {LURE}")
    ranked = [c["url"] for c in analysis.candidates]
    assert ranked[0] == LURE
    assert PRIVACY in ranked and UNSUBSCRIBE in ranked

    primary = root.get_observable(analysis.primary["observable_uuid"])
    assert primary.value == LURE
    assert primary.has_directive(DIRECTIVE_CRAWL)
    for observable in root.get_observables_by_type(F_URL):
        if observable.value != LURE:
            assert not observable.has_directive(DIRECTIVE_CRAWL)


@pytest.mark.integration
def test_engine_unwraps_safelinks(root_analysis, tmp_path):
    wrapper = "https://nam01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example.net%2Flogin&data=05&reserved=0"
    html = f'<p>Your mailbox is full.</p><a href="{wrapper}" class="button">Verify now</a>'

    root, analysis = _analyze(root_analysis, tmp_path, _message("mailbox full", html=html), ("protected_url_analyzer",))

    assert analysis.primary["url"] == "https://evil.example.net/login"
    assert analysis.primary["anchor_text"] == "Verify now"
    assert any(r.startswith("unwrapped from nam01.safelinks.protection.outlook.com") for r in analysis.primary["reasons"])
    assert wrapper not in [c["url"] for c in analysis.candidates]


@pytest.mark.integration
def test_engine_click_tracker_is_the_lure(root_analysis, tmp_path):
    html = f'<p>Your statement is ready.</p><a href="{TRACKER}">View statement</a>'

    root, analysis = _analyze(root_analysis, tmp_path, _message("statement", html=html))

    assert analysis.primary["url"] == TRACKER
    assert analysis.primary["anchor_text"] == "View statement"
    assert analysis.primary["carries"] == ["https://evil.example.net/login", "https://decoy.example.org/home"]
    assert "carries 2 URLs: evil.example.net/login, decoy.example.org/home" in analysis.primary["reasons"]
    # what the tracker carries is not ranked on its own
    assert [c["url"] for c in analysis.candidates] == [TRACKER]
    [tracker] = [o for o in root.get_observables_by_type(F_URL) if o.value == TRACKER]
    assert tracker.has_directive(DIRECTIVE_CRAWL)
    for observable in root.get_observables_by_type(F_URL):
        if observable.value != TRACKER:
            assert not observable.has_directive(DIRECTIVE_CRAWL)


def _bid_pdf() -> bytes:
    """A PDF with two links, each over its own line of text."""
    pdf = pikepdf.new()
    font = pdf.make_indirect(pikepdf.Dictionary(Type=pikepdf.Name.Font, Subtype=pikepdf.Name.Type1,
                                                BaseFont=pikepdf.Name.Helvetica))
    contents = pdf.make_stream(b"BT /F1 12 Tf 72 720 Td (View Bid Documents) Tj ET "
                               b"BT /F1 12 Tf 72 680 Td (www.contractor.example.com) Tj ET")
    links = [pdf.make_indirect(pikepdf.Dictionary(
        Type=pikepdf.Name.Annot, Subtype=pikepdf.Name.Link, Rect=rect,
        A=pikepdf.Dictionary(S=pikepdf.Name.URI, URI=pikepdf.String(url))))
        for url, rect in ((BID_PORTAL, [70, 715, 300, 732]), (CONTRACTOR, [70, 675, 300, 692]))]
    pdf.pages.append(pikepdf.Page(pikepdf.Dictionary(
        Type=pikepdf.Name.Page, MediaBox=[0, 0, 612, 792], Resources=pikepdf.Dictionary(Font=pikepdf.Dictionary(F1=font)),
        Contents=contents, Annots=pdf.make_indirect(pikepdf.Array(links)))))
    output = io.BytesIO()
    pdf.save(output)
    return output.getvalue()


@pytest.mark.integration
def test_engine_bid_pdf_link_beats_the_signature_link(root_analysis, tmp_path):
    message = _message("bid documents", html=THREAD_HTML,
                       text="Please review the attached bid documents and confirm by Friday.\nRespectfully,\nPat")
    message.add_attachment(_bid_pdf(), maintype="application", subtype="pdf", filename="bid.pdf")

    root, analysis = _analyze(root_analysis, tmp_path, message, ("pdf_analyzer", "pdf_link_text"))

    assert analysis.primary["url"] == BID_PORTAL
    assert analysis.primary["anchor_text"] == "View Bid Documents"
    assert "call-to-action text (view)" in analysis.primary["reasons"]
    assert any(r.startswith("the email refers to its attachment") for r in analysis.primary["reasons"])
    candidates = {c["url"]: c for c in analysis.candidates}
    assert "in a signature block" in candidates[SIGNATURE_LINK]["reasons"]
    assert candidates[CONTRACTOR]["anchor_text"] == "www.contractor.example.com"
    assert candidates[CONTRACTOR]["score"] < analysis.primary["score"]


@pytest.mark.integration
def test_engine_reported_email_prefers_the_inner_email(root_analysis, tmp_path):
    report = _message("FW: shared document", sender="reporter@internal.example.org",
                      text="Is this legit? https://helpdesk.example.info/report-phish")
    report.add_attachment(_message("shared document", html=LURE_HTML))

    root, outer = _analyze(root_analysis, tmp_path, report)

    assert outer.has_inner_email is True
    assert outer.primary["url"] == "https://helpdesk.example.info/report-phish"

    entries = build_lure_urls(root)
    assert [entry.primary["url"] for entry in entries] == [LURE, "https://helpdesk.example.info/report-phish"]
    assert entries[0].subject == "shared document"


@pytest.mark.integration
def test_engine_no_urls(root_analysis, tmp_path):
    root, analysis = _analyze(root_analysis, tmp_path, _message("hello", text="no links here"))

    assert analysis is False or analysis is None


@pytest.mark.integration
def test_engine_footer_links_only_have_no_primary(root_analysis, tmp_path):
    html = f'<p>Thanks for your order.</p><a href="{UNSUBSCRIBE}">Unsubscribe</a>'

    root, analysis = _analyze(root_analysis, tmp_path, _message("order", html=html))

    assert analysis.primary is None
    assert analysis.candidates[0]["url"] == UNSUBSCRIBE
    assert analysis.summary == "Lure URL Analysis: no lure URL identified"
    assert not any(o.has_directive(DIRECTIVE_CRAWL) for o in root.get_observables_by_type(F_URL))
    assert build_lure_urls(root) == []
