# vim: sw=4:ts=4:et

import logging
import os
import re

from subprocess import PIPE, Popen
from typing import Optional

from html2text import html2text

from saq.analysis.search import search_down

whitespace_re = re.compile(r'\s')


def wordlist_from_email(file_observable, range_low: int, range_high: int, byte_limit: int,
                        list_limit: int) -> tuple[bool, Optional[str], list[str]]:
    """Harvest candidate passwords from the body of the email that carried the given file.

    Returns (email_present, email_body, words): whether a carrying EmailAnalysis was found,
    the html-to-text email body (truncated to byte_limit) or None, and the wordlist generated
    from it.
    """
    # local import: saq.modules.email imports saq.cracking, so importing it at module level
    # here would be a circular import
    from saq.modules.email.rfc822 import EmailAnalysis

    email = search_down(file_observable, lambda obj: isinstance(obj, EmailAnalysis) and obj.email is not None)
    if not email:
        return False, None, []

    if not email.body:
        return True, None, []

    with open(email.body.full_path, 'r', errors='ignore') as fp:
        logging.debug("parsing {} for html".format(email.body.value))
        email_body = html2text(fp.read())[:byte_limit]

    words = generate_wordlist(text_content=email_body, range_low=range_low,
                              range_high=range_high, byte_limit=byte_limit, list_limit=list_limit)
    return True, email_body, words

def generate_wordlist(
        text_file: Optional[str]=None, 
        text_content: Optional[str]=None, 
        range_low: int=4, 
        range_high: int=14, 
        byte_limit: int=1024, 
        list_limit: int=1000,
        ) -> list[str]:
    """Given a text file or string, return a list of all the likely passwords, assuming the password is in there somewhere."""
    if text_content is None:
        with open(text_file, 'rb') as fp:
            data = fp.read(byte_limit).decode(errors='ignore')
    else:
        data = text_content[:byte_limit]

    # if we don't have anything to work with, return an empty list
    if not data:
        return []

    password_list = set()
    for r in range(range_low, range_high + 1):
        for i in range(0, len(data) - r + 1):
            password = data[i:i + r]
            if not password:
                continue

            # assume whitespace characters are not going to be in passwords
            if whitespace_re.search(password):
                continue

            password_list.add(password)
            if len(password_list) >= list_limit:
                return list(password_list)

    return list(password_list)

def crack_password(john_bin_path: str, hash_file: str, filename: str, mode: str, login: str | None = None) -> str | None:
    """Cracks the hash in hash_file with john and returns the password, or None.

    A hash file written as the single line '<login>:<hash>' names its login, which has no ':' in
    it, so everything after it on the --show line is the password, ':' included. Otherwise the
    line is found by the file's name and the password is its second ':' field, because
    zip2john and rar2john write more fields after the hash."""
    if not os.path.exists(hash_file):
        raise FileNotFoundError(f"hash file {hash_file} not found")

    john_bin = os.path.join(john_bin_path, 'john')
    if not os.path.exists(john_bin):
        raise FileNotFoundError(f"john binary {john_bin} not found")

    # john defaults to one session file and one pot for the whole install. a run refuses to start
    # while another holds the session ("Crash recovery file is locked"), so concurrent workers
    # cracking at the same time failed. each hash file gets its own session and pot instead
    session = f'--session={hash_file}.john'
    pot = f'--pot={hash_file}.pot'

    p = Popen([john_bin, session, pot, mode, hash_file], stdin=PIPE, stdout=PIPE,
              stderr=PIPE)
    _, stderr = p.communicate()
    if p.returncode != 0:
        logging.warning(f"john {mode} on {hash_file} exited with {p.returncode}: {stderr.decode(errors='ignore').strip()}")

    p = Popen([john_bin, pot, '--show', hash_file], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, _ = p.communicate()

    password = None
    for line in stdout.decode(errors='ignore').split('\n'):
        if login is not None:
            if line.startswith(f'{login}:'):
                password = line[len(login) + 1:]
        elif os.path.basename(filename) in line:
            password = line.split(':')[1]

    return password