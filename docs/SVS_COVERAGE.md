# SVS coverage

SVS coverage answers "which ATT&CK techniques do we actually detect?" from the Atomic Red Team test
runs that analysts review (`docs/SVS_RUNS.md`), together with the technique tags signatures already
carry (`docs/SVS.md`, Part 4).

This document covers how coverage works in ACE and how to operate it. It grows with phase 5. Today
it covers the ATT&CK release coverage is computed against. The design and its reasoning are in
`docs/SVS.md`; the API's data dictionary is `docs/SVS_API.md`.

## The ATT&CK release

Coverage needs ATT&CK itself for technique and tactic names, to roll sub-techniques up to their
parents, for each technique's platforms, and to know where a revoked technique went. Atomic Red
Team supplies only the technique id of each test.

**Production ACE never fetches ATT&CK.** Each supported release is vendored in this repository as a
compact extract, `etc/attack/<release>.json`. `etc/` is copied into the image. The setting
`svs.attack_release` (default `v20.0`) names the extract in use. Startup fails config validation
when that file is missing:

```
svs.attack_release v21.0: /opt/ace/etc/attack/v21.0.json is missing; bin/update-attack-catalog v21.0 builds it
```

### What the extract holds

The extract is built from MITRE's enterprise STIX bundle for the release. It holds only what SVS
uses:

| Key | Contents |
|---|---|
| `release`, `domain`, `source` | The release (`v20.0`), `enterprise-attack`, and the URL and sha256 of the bundle it was built from |
| `platforms` | The platform slugs coverage uses, in display order, with ATT&CK's name for each |
| `tactics` | Every tactic in the matrix's order: id (`TA0002`), shortname (`execution`), name |
| `techniques` | Per technique id (`T1059`, `T1059.001`): name, parent (sub-techniques only), tactic ids, platform slugs, and `deprecated` |
| `revoked` | Revoked id → the current technique that replaces it |
| `renamed` | Informational: techniques whose name changed since a previous extract |

**Platforms** get stable slugs: `windows`, `linux`, `macos`, `esxi`, `iaas`, `containers`, `saas`,
`office-suite`, `identity-provider`, `network-devices`, `pre`. Older ATT&CK names map onto them
("Office 365" and "Google Workspace" → `office-suite`, "Azure AD" → `identity-provider`,
"Network" → `network-devices`). A test's `supported_platforms` uses Atomic Red Team's names, which
map the same way: `iaas:aws`, `iaas:azure` and `iaas:gcp` → `iaas`, `azure-ad` →
`identity-provider`, `office-365` and `google-workspace` → `office-suite`.

**Revoked, deprecated and renamed** mean different things:
- **Revoked.** ATT&CK replaced the technique with another one, often when it became a
  sub-technique (T1086 PowerShell → T1059.001). Wherever SVS reads a technique id, from an atomic
  or a signature's tag, a revoked id counts as its successor. Revocations of revocations are
  followed to the end (T1150 → T1547.011 → T1647).
- **Deprecated.** ATT&CK retired the technique without a replacement. It keeps its id, name and
  platforms in the extract, marked `deprecated`, so a test or tag that still names it isn't lost.
- **Renamed.** A rename keeps the technique's id, and ids are the key everywhere in SVS, so a
  rename needs no remapping: names always come from the pinned release. One STIX bundle can't show
  that a rename happened, so `renamed` is filled only when the extract is built with `--previous`,
  for the upgrade notes.

An id that isn't in the release at all, such as a custom atomic's technique or a typo, is kept as it
is and shown as *unknown*.

### Adding or upgrading a release

`bin/update-attack-catalog` builds an extract. It is a developer tool and needs network access to
GitHub. It downloads `enterprise-attack/enterprise-attack-<version>.json` from MITRE's
[attack-stix-data](https://github.com/mitre-attack/attack-stix-data) repository:

```bash
bin/update-attack-catalog v21.0 --previous etc/attack/v20.0.json
```

- `--input FILE` builds from a bundle already on disk instead of downloading it.
- `--output-dir DIR` writes somewhere other than `etc/attack/`.
- The output is deterministic, so rebuilding a release writes the same bytes, and a new release
  reviews as a readable diff against the previous one.
- The build stops on anything it can't place, rather than dropping it:
  - a platform name it has no slug for (add it to `PLATFORMS` or `PLATFORM_NAMES` in the script);
  - a tactic the bundle doesn't define;
  - a cycle of revocations;
  - a bundle that says it is a different release.
- A revoked technique whose successor is missing from the bundle is left out of `revoked`, with a
  warning.

To move a site to the new release, commit the extract and change `attack_release`. Keep the
previous extract in the repository until no site uses it.
