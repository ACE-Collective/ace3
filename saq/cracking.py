# vim: sw=4:ts=4:et

import os
import re

from subprocess import PIPE, Popen
from typing import Optional

whitespace_re = re.compile(r'\s')

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

def crack_password(john_bin_path: str, hash_file: str, filename: str, mode: str) -> str | None:
    if not os.path.exists(hash_file):
        raise FileNotFoundError(f"hash file {hash_file} not found")

    john_bin = os.path.join(john_bin_path, 'john')
    if not os.path.exists(john_bin):
        raise FileNotFoundError(f"john binary {john_bin} not found")

    p = Popen([john_bin, mode, hash_file], stdin=PIPE, stdout=PIPE,
              stderr=PIPE)
    _, _ = p.communicate()

    p = Popen([john_bin, '--show', hash_file], stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, _ = p.communicate()

    password = None
    for line in stdout.decode(errors='ignore').split('\n'):
        if os.path.basename(filename) in line:
            password = line.split(':')[1]

    return password