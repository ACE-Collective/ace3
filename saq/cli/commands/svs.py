"""``ace svs`` -- the Signature Validation System (docs/SVS.md).

``yara validate`` replays every stored sample under two commits of a rule repository and prints
what changed, synchronously and without storing anything (docs/SVS_VALIDATION.md); the queued
validations CI requests are run by service_svs instead. ``yara layout`` prints which directories of
each repository in svs.yara.repositories the yara service loads. ``yara prune`` removes the
validations older than svs.yara.retention_days (daily cron). ``catalog refresh`` reads the Atomic
Red Team catalog repositories (service_svs does it on its own) and ``catalog status`` prints them
(docs/SVS_RUNS.md).
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
    from saq.svs.actions import retired_pairs
    from saq.svs.yara.replay import ReplayError, run_replay

    try:
        # a retired sample is only counted, as the validation service counts it
        result = run_replay(args.repository, args.base, args.head, branch=args.branch, retired=retired_pairs())
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


def cli_prune(args):
    """Remove the finished validations older than svs.yara.retention_days."""
    from saq.database.util.node import is_primary_node
    from saq.svs.validations import prune

    # the validations are shared state: the primary node prunes them
    if not (is_primary_node() or args.force):
        print("skipping: not the primary node (use --force to prune anyway)")
        return 0

    count = prune(dry_run=args.dry_run)
    print(f"{'would remove' if args.dry_run else 'removed'} {count} validations")
    return 0


prune_parser = svs_yara_sp.add_parser("prune", help="Remove the validations older than svs.yara.retention_days.")
prune_parser.add_argument("--dry-run", action="store_true", default=False, help="Count them without removing anything.")
prune_parser.add_argument("--force", action="store_true", default=False, help="Prune even when this is not the primary node.")
prune_parser.set_defaults(func=cli_prune)


svs_catalog_parser = svs_sp.add_parser("catalog", help="The Atomic Red Team test catalog.")
svs_catalog_sp = svs_catalog_parser.add_subparsers(dest="svs_catalog_cmd")


def cli_catalog_refresh(args):
    """Read each catalog repository's tests whose checkout has a new commit."""
    from saq.svs.catalog import refresh_catalog, refresh_repository

    results = [refresh_repository(args.repository, force=args.force)] if args.repository else refresh_catalog(force=args.force)
    if not results:
        print("svs.catalog.repositories is empty")
        return 0

    status = 0
    for result in results:
        if result.error:
            print(f"{result.repository}: {result.error}")
            status = 1
        elif result.refreshed:
            print(f"{result.repository} @ {_short(result.commit)}: {result.tests} tests ({result.added} added, "
                  f"{result.changed} changed, {result.removed} removed, {len(result.skipped)} skipped)")
            for path, name, reason in result.skipped:
                print(f"  skipped {path}{f' ({name})' if name else ''}: {reason}")
        else:
            print(f"{result.repository} @ {_short(result.commit or '?')}: already read (--force to read it again)")

    return status


catalog_refresh_parser = svs_catalog_sp.add_parser(
    "refresh", help="Read the tests of each catalog repository whose commit changed (service_svs does this on its own).")
catalog_refresh_parser.add_argument("--repository", help="Only this repository (one of svs.catalog.repositories).")
catalog_refresh_parser.add_argument("--force", action="store_true", default=False, help="Read the tests even if the commit did not change.")
catalog_refresh_parser.set_defaults(func=cli_catalog_refresh)


def cli_catalog_status(args):
    """Print each catalog repository's commit, test count and last error."""
    from sqlalchemy import func

    from saq.configuration.config import get_config
    from saq.database.model import SVSCatalogRepository, SVSCatalogTest
    from saq.database.pool import get_db

    configured = get_config().svs.catalog.repositories
    rows = {row.name: row for row in get_db().query(SVSCatalogRepository)}
    removed = dict(get_db().query(SVSCatalogTest.repository, func.count(SVSCatalogTest.id))
                   .filter(SVSCatalogTest.removed_at.isnot(None)).group_by(SVSCatalogTest.repository))
    for name in sorted(set(configured) | set(rows)):
        row = rows.get(name)
        state = "" if name in configured else " (no longer in svs.catalog.repositories)"
        if row is None or row.refreshed_at is None:
            print(f"{name}{state}: never read" + (f"; last error: {row.error}" if row is not None and row.error else ""))
            continue

        print(f"{name}{state}: {row.test_count} tests at {_short(row.commit)}, read {row.refreshed_at}, "
              f"{row.skipped_count} skipped, {removed.get(name, 0)} removed since"
              + (f"; last error: {row.error}" if row.error else ""))
    return 0


catalog_status_parser = svs_catalog_sp.add_parser("status", help="Print each catalog repository's commit and test count.")
catalog_status_parser.set_defaults(func=cli_catalog_status)
