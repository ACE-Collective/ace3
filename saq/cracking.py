# vim: sw=4:ts=4:et

import logging
import os
import string

from collections.abc import Sequence
from typing import TYPE_CHECKING, Optional

from html2text import html2text

from saq.analysis.search import search_down
from saq.modules.email.rfc822 import EmailAnalysis

if TYPE_CHECKING:
    from saq.modules.base_module import AnalysisModule


def wordlist_from_email(file_observable, range_low: int, range_high: int, byte_limit: int,
                        list_limit: int) -> tuple[bool, Optional[str], list[str]]:
    """Harvest candidate passwords from every body part of the email that carried the given file.

    Every part is read, not only the one EmailAnalysis.body picks: the html alternative can leave
    out the password the text/plain one carries, and a gateway banner can be the first html part.

    Returns (email_present, email_body, words): whether a carrying EmailAnalysis was found, the
    text of its distinct body parts (html converted to text, each part cut at byte_limit) or None
    when it has none, and the wordlist generated from that text.
    """
    email = search_down(file_observable, lambda obj: isinstance(obj, EmailAnalysis) and obj.email is not None)
    if not email:
        return False, None, []

    texts = []
    for part in email.body_parts:
        with open(part.full_path, 'r', errors='ignore') as fp:
            content = fp.read()

        if '.unknown_text_html' in part.file_name:
            content = html2text(content)

        text = content.strip()[:byte_limit]
        # the html part is often the text/plain part again
        if text and text not in texts:
            texts.append(text)

    if not texts:
        return True, None, []

    email_body = '\n\n'.join(texts)
    words = generate_wordlist(text_content=email_body, range_low=range_low, range_high=range_high,
                              byte_limit=len(email_body), list_limit=list_limit)
    return True, email_body, words

def generate_wordlist(
        text_file: Optional[str]=None,
        text_content: Optional[str]=None,
        range_low: int=4,
        range_high: int=14,
        byte_limit: int=1024,
        list_limit: int=1000,
        ) -> list[str]:
    """Given a text file or string, return a list of all the likely passwords, assuming the password is in there somewhere.

    A password is assumed to have no whitespace in it. The candidates are every word, as written
    and without the punctuation around it, then every substring of a word, shortest first, so
    list_limit drops the substrings of long words before it drops a word."""
    if text_content is None:
        with open(text_file, 'rb') as fp:
            data = fp.read(byte_limit).decode(errors='ignore')
    else:
        data = text_content[:byte_limit]

    words = data.split()
    # a dict keeps the candidates in the order they were added
    candidates: dict[str, None] = {}

    def _add(candidate: str) -> bool:
        """Adds the candidate if its length is in range; returns whether the list is full."""
        if range_low <= len(candidate) <= range_high:
            candidates.setdefault(candidate)
        return len(candidates) >= list_limit

    for word in words:
        for candidate in (word, word.strip(string.punctuation)):
            if _add(candidate):
                return list(candidates)

    for r in range(range_low, range_high + 1):
        for word in words:
            for i in range(0, len(word) - r + 1):
                if _add(word[i:i + r]):
                    return list(candidates)

    return list(candidates)

def crack_password(module: "AnalysisModule", john_bin_path: str, hash_file: str, filename: str, mode: str,
                   login: str | None = None, read_files: Sequence[str] = ()) -> str | None:
    """Cracks the hash in hash_file with john and returns the password, or None, also when john was
    stopped or could not be run. john runs in the module's sandbox (run_sandboxed_tool): the hash
    is the attacker's file's, and the wordlist comes from the email. read_files are the files mode
    names (the wordlist), which john may read besides the hash file.

    A hash file written as the single line '<login>:<hash>' names its login, which has no ':' in
    it, so everything after it on the --show line is the password, ':' included. Otherwise the
    line is found by the file's name and the password is its second ':' field, because
    zip2john and rar2john write more fields after the hash."""
    if not os.path.exists(hash_file):
        raise FileNotFoundError(f"hash file {hash_file} not found")

    john_bin = os.path.join(john_bin_path, 'john')
    if not os.path.exists(john_bin):
        raise FileNotFoundError(f"john binary {john_bin} not found")

    # john defaults to one session file and one pot for the whole install, where a run refuses to
    # start while another holds the session ("Crash recovery file is locked"). each run has a
    # working directory of its own for them, and the pot is kept for the --show that follows
    pot = os.path.abspath(f'{hash_file}.pot')
    result = module.run_sandboxed_tool([john_bin, '--session=john', '--pot=john.pot', mode, hash_file], hash_file,
                                       read_files=read_files, outputs={'john.pot': pot})
    if result is None:
        return None

    if result.returncode != 0:
        logging.warning(f"john {mode} on {hash_file} exited with {result.returncode}: {result.stderr.strip()}")

    # a run that found nothing may leave no pot
    if not os.path.exists(pot):
        return None

    result = module.run_sandboxed_tool([john_bin, f'--pot={pot}', '--show', hash_file], hash_file, read_files=[pot])
    if result is None:
        return None

    password = None
    for line in result.stdout.split('\n'):
        if login is not None:
            if line.startswith(f'{login}:'):
                password = line[len(login) + 1:]
        elif os.path.basename(filename) in line:
            password = line.split(':')[1]

    return password
