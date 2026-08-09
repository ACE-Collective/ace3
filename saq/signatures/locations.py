"""Where ACE loads signatures from

The loaders in saq/signatures/loaders/ each need to be handed a path. This is
the piece that works out what those paths are, by reading the same configuration
the detection path reads - so an inventory built from these locations describes
what this deployment actually loads.

Two things follow from that and are deliberate:

    * an initialized configuration is required (initialize_environment()). these
      functions do not load one themselves.
    * a signature source that is turned off contributes no locations at all. a
      disabled observable modifier module and a hunt type that is not
      schedulable load nothing, so there is nothing to report.
"""

from collections.abc import Callable
import logging
import os

from saq.configuration.config import get_config, get_service_config
from saq.constants import ANALYSIS_MODULE_OBSERVABLE_MODIFIER, SERVICE_YARA_SCANNER
from saq.signatures.model import SignatureLocation, SignatureType
from saq.util.filesystem import abs_path

CONFIG_SERVICE_YARA = f"service_{SERVICE_YARA_SCANNER}"
CONFIG_ANALYSIS_MODULE_OBSERVABLE_MODIFIER = f"analysis_module_{ANALYSIS_MODULE_OBSERVABLE_MODIFIER}"


def _yara_locations() -> list[SignatureLocation]:
    """service_yara.signature_dir, versioned by service_yara.git_repo_dirs."""
    from saq.yara_scanning_service import get_validated_git_repo_dirs

    try:
        config = get_service_config(SERVICE_YARA_SCANNER)
    except ValueError:
        logging.warning("no %s configuration - no yara signatures are loaded", CONFIG_SERVICE_YARA)
        return []

    # The location is the signature_dir itself rather than one per rule
    # subdirectory: the loader mirrors YaraScanner's traversal of it, which is
    # what keeps generated directories like observable_export out of the
    # inventory. It also matches the shape of the configuration block.
    signature_dir = abs_path(config.signature_dir)

    # get_validated_git_repo_dirs drops entries that are not a directory or not
    # in a repo (logging why), which is what the scanner is actually given.
    # Entries come back as configured, so resolve them the way
    # YaraScanner._resolve_signature_subdir does to keep git_dirs absolute.
    git_dirs = tuple(
        entry if os.path.isabs(entry) else os.path.join(signature_dir, entry)
        for entry in get_validated_git_repo_dirs()
    )

    return [SignatureLocation(
        signature_type=SignatureType.YARA,
        path=signature_dir,
        git_dirs=git_dirs,
        source=CONFIG_SERVICE_YARA,
    )]


def _hunt_locations() -> list[SignatureLocation]:
    """every rule_dir of every schedulable hunt_type_<type>."""
    result = []
    for hunt_type in get_config().hunt_types:
        if not hunt_type.schedulable:
            # rule_dirs of a non schedulable type are never scanned, so no hunt
            # of this type is ever loaded
            logging.debug("hunt type %s is not schedulable - skipping its rule dirs", hunt_type.name)
            continue

        for entry in hunt_type.rule_dirs:
            # entries here are always a validated HuntRuleDirConfig. HuntManager
            # additionally tolerates dicts and bare strings from internal
            # callers, but reusing its normalizer would drag the whole hunter
            # package into saq.signatures for nothing.
            result.append(SignatureLocation(
                signature_type=SignatureType.HUNT,
                path=abs_path(entry.rule_dir),
                git_dirs=(abs_path(entry.git_dir),) if entry.git_dir else (),
                source=f"hunt_type_{hunt_type.name}",
            ))

    return result


def _observable_modifier_locations() -> list[SignatureLocation]:
    """the single rules file of the observable modifier module."""
    from saq.modules.util.observable_modifier import ObservableModifierConfig

    try:
        config = get_config().get_analysis_module_config(ANALYSIS_MODULE_OBSERVABLE_MODIFIER)
    except ValueError:
        logging.warning(
            "no %s configuration - no observable modifier signatures are loaded",
            CONFIG_ANALYSIS_MODULE_OBSERVABLE_MODIFIER)
        return []

    if not isinstance(config, ObservableModifierConfig):
        # the block can be repointed at another class, in which case it has no
        # rules file to read
        logging.error(
            "%s is not configured as an observable modifier (python_class is %s)",
            CONFIG_ANALYSIS_MODULE_OBSERVABLE_MODIFIER, config.python_class)
        return []

    if not config.enabled:
        logging.warning(
            "%s is disabled - its rules are never loaded",
            CONFIG_ANALYSIS_MODULE_OBSERVABLE_MODIFIER)
        return []

    return [SignatureLocation(
        signature_type=SignatureType.OBSERVABLE_MODIFIER,
        path=abs_path(config.rules_config_path),
        git_dirs=(abs_path(config.git_dir),) if config.git_dir else (),
        source=CONFIG_ANALYSIS_MODULE_OBSERVABLE_MODIFIER,
    )]


def _builtin_locations() -> list[SignatureLocation]:
    """built-in signatures are a static table in saq/signatures/builtin.py, not
    something loaded from disk, so they have no location."""
    return []


LOCATION_RESOLVERS: dict[SignatureType, Callable[[], list[SignatureLocation]]] = {
    SignatureType.YARA: _yara_locations,
    SignatureType.HUNT: _hunt_locations,
    SignatureType.OBSERVABLE_MODIFIER: _observable_modifier_locations,
    SignatureType.BUILTIN: _builtin_locations,
}


def get_signature_locations(signature_type: SignatureType) -> list[SignatureLocation]:
    """Returns every location the current configuration loads signatures of this
    type from. Empty is a valid answer: nothing is configured, or what is
    configured is turned off."""
    resolver = LOCATION_RESOLVERS.get(signature_type)
    if resolver is None:
        raise ValueError(f"no signature locations for type {signature_type}")

    return resolver()


def get_all_signature_locations() -> list[SignatureLocation]:
    """Returns the locations of every signature type, in SignatureType order."""
    result = []
    for signature_type in SignatureType:
        result.extend(get_signature_locations(signature_type))

    return result
