"""``ace svs`` -- the Signature Validation System (docs/SVS.md).

``yara validate`` replays every stored sample under two commits of a rule repository and prints
what changed, synchronously and without storing anything (docs/SVS_VALIDATION.md). ``yara layout``
prints which directories of each repository in svs.yara.repositories the yara service loads.
"""

import json
import sys

from saq.cli.cli_main import get_cli_subparsers

# NOTE the saq.svs imports below are inside their command functions on purpose, matching the
# convention in this package (see cas.py): this module is imported on every `ace` invocation just to
# register its parsers, and saq.svs pulls in the config, the database models and the CAS.

svs_parser = get_cli_subparsers().add_parser("svs", help="The Signature Validation System (docs/SVS.md).")
svs_sp = svs_parser.add_subparsers(dest="svs_cmd")

svs_yara_parser = svs_sp.add_parser("yara", help="YARA rule validation.")
svs_yara_sp = svs_yara_parser.add_subparsers(dest="svs_yara_cmd")


# the report's bands, most urgent first: (category, heading)
REPORT_BANDS = (
    ("regression", "Regressions"),
    ("regression_unconfirmed", "Regressions on unconfirmed labels (check that the sample was ever a real hit for the rule)"),
    ("new_fp", "New false positives"),
    ("new_fp_other_rule", "New false positives on another rule's sample"),
    ("rule_removed", "Samples of rules head removed"),
    ("scan_error", "Scan errors"),
    ("recovered", "Recovered"),
    ("improvement", "Improvements"),
    ("already_broken", "Already broken on base"),
    ("new_match_real_hit", "New matches on files that are a real hit for another rule"),
    ("unlabeled_change", "Unlabeled changes"),
)


def _short(sha: str) -> str:
    return sha[:12]


def _print_side(name: str, side) -> None:
    print(f"{name} {_short(side.sha)}: {side.rule_count} rules in {len(side.timings)} namespaces "
          f"({', '.join(side.namespaces) or 'none'})")
    for namespace in side.absent_namespaces:
        print(f"  namespace {namespace} does not exist in this commit")
    for error in side.file_errors:
        print(f"  {error.file} does not compile, its {len(error.dropped)} rule(s) are dropped: {error.error}")
    if side.ruleset_error:
        print(f"  the ruleset would not load, so production keeps its previous rules: {side.ruleset_error}")
    for warning in side.include_warnings:
        print(f"  {warning['file']}: include {warning['include']}: {warning['error']}")
    for item in side.not_loaded:
        print(f"  not loaded: {item.path} ({item.reason})")
    for path, reason in side.skipped_members:
        print(f"  not exported: {path} ({reason})")


def print_report(result) -> None:
    print(f"repository {result.repository}: base {_short(result.base_sha)}, head {_short(result.head_sha)}")
    print(f"corpus: {result.files} files, {result.units} scans, {result.samples} samples, {result.bytes} bytes "
          f"({result.duration_seconds:.1f}s)")
    if result.skipped:
        print(f"  {len(result.skipped)} not replayed:")
        for skipped in result.skipped:
            print(f"    {skipped.sha256} {skipped.file_path or ''} {skipped.reason} {skipped.detail}".rstrip())
    if result.truncated_paths:
        print(f"  {result.truncated_paths} scans use a path that was cut when it was stored")

    _print_side("base", result.base)
    _print_side("head", result.head)

    print(f"rules: {len(result.added_rules)} added, {len(result.removed_rules)} removed, "
          f"{len(result.changed_rules)} changed")
    for label, refs in (("added", result.added_rules), ("removed", result.removed_rules),
                        ("changed", result.changed_rules)):
        for ref in refs:
            print(f"  {label} {ref.name} ({ref.uuid}) in {ref.file}")

    if not result.diffed:
        print("nothing was compared: a ruleset would not load")
        return

    print("counts: " + ", ".join(f"{name} {count}" for name, count in result.counts.items() if count))
    for category, heading in REPORT_BANDS:
        rows = [row for row in result.rows if row.category == category]
        if not rows:
            continue

        print(f"{heading} ({len(rows)}):")
        for row in rows:
            if row.label:
                label = f"{row.label} ({row.label_source})"
            elif row.category in ("new_fp_other_rule", "new_match_real_hit"):
                label = "another rule's sample"
            else:
                label = "unlabeled"
            print(f"  {row.sha256} {row.rule_name} ({row.rule_uuid}) {label}: base {row.base}, head {row.head}"
                  + (f" -- {row.note}" if row.note else ""))

    for item in result.not_testable:
        print(f"not testable: {item['name']} ({item['uuid']}) in {item['file']}: {item['reason']}")
    for ref in result.full_path_rules:
        print(f"filters on full_path, which a replay cannot reproduce: {ref.name} ({ref.uuid}) in {ref.file}")
    for warning in result.head.warnings:
        print(f"head compiler warning: {warning}")

    print("scan time per namespace (base / head):")
    for namespace in sorted(set(result.base.timings) | set(result.head.timings)):
        base = result.base.timings.get(namespace, {}).get("scan_seconds")
        head = result.head.timings.get(namespace, {}).get("scan_seconds")
        print(f"  {namespace}: {'-' if base is None else f'{base:.2f}s'} / {'-' if head is None else f'{head:.2f}s'}")


def cli_validate(args):
    """Validate a commit of a rule repository against another."""
    from saq.svs.yara.replay import ReplayError, run_replay

    try:
        result = run_replay(args.repository, args.base, args.head, branch=args.branch)
    except ReplayError as e:
        print(f"validation failed: {e}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, default=str))
    else:
        print_report(result)

    return 0


validate_parser = svs_yara_sp.add_parser("validate", help="Replay the samples under two commits and print what changed.")
validate_parser.add_argument("--repository", required=True, help="A repository named in svs.yara.repositories.")
validate_parser.add_argument("--base", required=True, help="The commit to compare against (the merge base of a PR).")
validate_parser.add_argument("--head", required=True, help="The commit to validate.")
validate_parser.add_argument("--branch", help="The branch the head commit is on (default: the repository's branch).")
validate_parser.add_argument("--json", action="store_true", default=False, help="Print the result as JSON.")
validate_parser.set_defaults(func=cli_validate)


def cli_layout(args):
    """Print the namespaces each repository feeds the yara service."""
    from saq.configuration.config import get_config
    from saq.svs.yara.layout import LayoutError, resolve_layout

    status = 0
    for repository in get_config().svs.yara.repositories:
        try:
            layout = resolve_layout(repository)
        except LayoutError as e:
            print(f"{repository}: {e}")
            status = 1
            continue

        if layout.contained:
            print(f"{repository}: every directory of {layout.signature_dir_path or 'the repository root'} is a namespace")
        else:
            for namespace in layout.namespaces:
                print(f"{repository}: namespace {namespace.name} is {namespace.path or 'the repository root'}")

    return status


layout_parser = svs_yara_sp.add_parser("layout", help="Print which directories of each repository the yara service loads.")
layout_parser.set_defaults(func=cli_layout)
