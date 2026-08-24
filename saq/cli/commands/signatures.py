"""ace signatures - the detection signature inventory

`list` answers "what signatures is this deployment running, and at what
version?", and `locations` answers "where is it loading them from?" - the second
still works when the first cannot, which is exactly when you need it."""

import sys

from saq.cli.cli_main import get_cli_subparsers
from saq.signatures.model import SignatureType

# a git commit hash is unreadable at full length in a table, but the other things
# that land in the version column (an ACE version, "unknown") are not hashes and
# must not be cut
COMMIT_HASH_LENGTH = 40
ABBREVIATED_COMMIT_HASH_LENGTH = 12

signatures_parser = get_cli_subparsers().add_parser("signatures", help="Detection signature inventory.")
# required so that a bare `ace signatures` prints usage instead of failing on a
# missing func attribute
signatures_sp = signatures_parser.add_subparsers(dest="signatures_cmd", required=True)


def _requested_types(args) -> list[SignatureType]:
    """Returns the types named by -t/--type, or all of them."""
    if not args.type:
        return list(SignatureType)

    return [SignatureType(value) for value in args.type]


def _abbreviate_version(version: str) -> str:
    try:
        int(version, 16)
    except ValueError:
        return version

    if len(version) != COMMIT_HASH_LENGTH:
        return version

    return version[:ABBREVIATED_COMMIT_HASH_LENGTH]


def _add_common_arguments(parser):
    parser.add_argument("-t", "--type", action="append", choices=[t.value for t in SignatureType],
        help="Limit the output to this signature type. May be specified more than once. Defaults to all types.")
    parser.add_argument("--json", action="store_true",
        help="Output JSON instead of a table.")


def _load_signatures(args) -> int:
    # imported lazily so importing the parser at ace startup stays cheap
    import dataclasses
    import json
    import logging

    from tabulate import tabulate

    from saq.signatures.loaders import load_builtin_signatures, load_from_location
    from saq.signatures.locations import get_signature_locations

    signatures = []
    failed = False

    for signature_type in _requested_types(args):
        if signature_type == SignatureType.BUILTIN:
            signatures.extend(load_builtin_signatures())
            continue

        for location in get_signature_locations(signature_type):
            try:
                loaded = load_from_location(location)
            except Exception as e:
                # one unreadable location must not cost us the whole listing -
                # a missing signature directory is a normal state on a node that
                # does not have the rule repo checked out
                logging.error("unable to load %s signatures from %s: %s", signature_type, location.path, e)
                failed = True
                continue

            if args.verbose:
                sys.stderr.write(f"{len(loaded)} {signature_type} signatures from {location.path}\n")

            signatures.extend(loaded)

    # Signature is frozen and hashable, so this drops the exact duplicates that
    # come from the same rule directory being configured twice
    signatures = list(dict.fromkeys(signatures))
    signatures.sort(key=lambda s: (s.type, s.source_path, s.name))

    if args.json:
        print(json.dumps([
            {**dataclasses.asdict(signature), "tags": list(signature.tags)}
            for signature in signatures
        ], indent=4))
    else:
        table = [[
            signature.type,
            signature.name,
            signature.uuid,
            _abbreviate_version(signature.version),
            ",".join(signature.tags),
            signature.source_path,
        ] for signature in signatures]

        headers = ["Type", "Name", "UUID", "Version", "Tags", "Source Path"]
        print(tabulate(table, headers=headers, tablefmt="github"))

    counts = {}
    for signature in signatures:
        counts[signature.type] = counts.get(signature.type, 0) + 1

    # to stderr so it does not end up in a piped table or json document
    breakdown = ", ".join(f"{signature_type}={count}" for signature_type, count in sorted(counts.items()))
    sys.stderr.write(f"{len(signatures)} signatures ({breakdown})\n" if breakdown else "0 signatures\n")

    # the same uuid appearing with different content is an authoring or
    # configuration bug: detections stamped with it cannot be traced back to one
    # signature
    seen = {}
    for signature in signatures:
        key = (signature.type, signature.uuid)
        if key in seen and seen[key] != (signature.content_hash, signature.source_path):
            sys.stderr.write(
                f"WARNING: {signature.type} uuid {signature.uuid} is used by more than one signature "
                f"({seen[key][1]} and {signature.source_path})\n")

        seen[key] = (signature.content_hash, signature.source_path)

    return 1 if failed else 0


def cli_list_signatures(args):
    """List the metadata of every signature loaded at the current git version."""
    sys.exit(_load_signatures(args))


list_signatures_parser = signatures_sp.add_parser("list",
    help="List the signatures ACE loads, with the version each one would stamp on a detection.")
_add_common_arguments(list_signatures_parser)
list_signatures_parser.add_argument("-v", "--verbose", action="store_true",
    help="Report what was loaded from each location to stderr.")
list_signatures_parser.set_defaults(func=cli_list_signatures)


def _list_locations(args) -> int:
    # imported lazily so importing the parser at ace startup stays cheap
    import dataclasses
    import json

    from tabulate import tabulate

    from saq.git import get_commit_hash
    from saq.signatures.locations import get_signature_locations

    locations = []
    for signature_type in _requested_types(args):
        locations.extend(get_signature_locations(signature_type))

    if args.json:
        print(json.dumps([
            {**dataclasses.asdict(location), "git_dirs": list(location.git_dirs), "exists": location.exists()}
            for location in locations
        ], indent=4))
    else:
        table = []
        for location in locations:
            # reading the commit here rather than loading the signatures is the
            # point of this command: it answers "why is this rule set unknown?"
            # without parsing a single rule
            versions = [get_commit_hash(git_dir) or "unknown" for git_dir in location.git_dirs]
            table.append([
                location.signature_type,
                location.source,
                location.path,
                "yes" if location.exists() else "no",
                "\n".join(location.git_dirs),
                "\n".join(_abbreviate_version(version) for version in versions),
            ])

        headers = ["Type", "Source", "Path", "Exists", "Git Dirs", "Version"]
        print(tabulate(table, headers=headers, tablefmt="github"))

        #if SignatureType.BUILTIN in _requested_types(args):
            #sys.stderr.write("builtin: none - built-in signatures are compiled into ACE\n")

    # usable as a configuration check: a configured location that is not there
    # loads nothing
    return 1 if any(not location.exists() for location in locations) else 0


def cli_list_locations(args):
    """List the locations signatures are loaded from, as the configuration declares them."""
    sys.exit(_list_locations(args))


list_locations_parser = signatures_sp.add_parser("locations",
    help="List where ACE loads signatures from, and which git checkout versions each one.")
_add_common_arguments(list_locations_parser)
list_locations_parser.set_defaults(func=cli_list_locations)
