from datetime import datetime, timedelta
import inspect
import logging
import math
import os
import shutil
import signal
import stat
import subprocess
import time
from collections.abc import Sequence
from typing import TYPE_CHECKING, Optional, Type, Union
from saq.analysis.analysis import Analysis, close_with_error
from saq.analysis.errors import AnalysisError
from saq.analysis.interfaces import RootAnalysisInterface
from saq.analysis.module_path import MODULE_PATH
from saq.analysis.observable import Observable
from saq.configuration.config import get_config
from saq.constants import (
    DIRECTIVE_EXCLUDE_ALL,
    DIRECTIVE_IGNORE_AUTOMATION_LIMITS,
    F_FILE,
)
from saq.constants import AnalysisExecutionResult
from saq.environment import get_base_dir, get_data_dir
from saq.filesystem.notification import FileWatcherMixin
from saq.modules.config import AnalysisModuleConfig
from saq.modules.context import AnalysisModuleContext
from saq.observables.type_hierarchy import get_type_hierarchy
from saq.util.filesystem import is_path_under
from saq.sandbox.runner import (
    NODE_FAILURE_EXIT_CODES,
    SandboxCancelled,
    SandboxOutputExceeded,
    SandboxResult,
    build_sandbox_argv,
    create_workdir,
    get_read_dirs,
    landlock_available,
    run_sandboxed,
    sweep_stale_workdirs,
)

if TYPE_CHECKING:
    pass


# how long before its call to analyze() runs out of time run_tool() stops a tool, so that the module
# still returns before the engine's watchdog kills the whole worker
TOOL_TIMEOUT_MARGIN_SECONDS = 5

# the tools run_sandboxed_tool() could not run, as "<module>:<program>": each is reported with an
# error report once per process, not once per file
_REPORTED_SANDBOX_FAILURES: set[str] = set()

# the sandbox work roots swept for directories a killed worker left behind, once per process
_SWEPT_WORK_ROOTS: set[str] = set()

# a program's own directory is readable to it in the sandbox unless it is one of these, or holds
# SAQ_HOME or the data directory: a tool installed there would expose everything under it
_NEVER_TOOL_DIRS = ("/", "/etc", "/home", "/root", "/auth", "/tmp", "/proc", "/var", "/opt")


def _tool_dirs(program: str) -> list[str]:
    """The directory of the program a sandboxed tool runs, when the fixed allowlist does not cover it
    (/opt/dotnet for ilspycmd, john's run directory). Raises ValueError for one that must not be
    readable."""
    directory = os.path.dirname(os.path.realpath(program))
    if any(is_path_under(directory, path) for path in get_read_dirs()):
        return []

    if directory in _NEVER_TOOL_DIRS or any(
            root and is_path_under(root, directory) for root in (get_base_dir(), get_data_dir())):
        raise ValueError(f"{program} is in {directory}, which cannot be made readable to the tool")

    return [directory]


def _sweep_tool_workdirs(work_root: str):
    if work_root not in _SWEPT_WORK_ROOTS:
        _SWEPT_WORK_ROOTS.add(work_root)
        sweep_stale_workdirs(work_root)


def _keep_tool_output(path: str, destination: str) -> bool:
    """Moves a file a sandboxed tool wrote to where the module keeps it, and returns False when the
    tool left something there that is not one. The tool may have left anything there, so only a plain
    file with a single link is taken: not a symlink to a file of ACE's, not a hard link to one. The
    launcher has killed everything the tool started, so nothing can swap the path after it is checked."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        # the tool did not write this output, which is how most tools fail
        return True

    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        return False

    shutil.move(path, destination)
    return True


class AnalysisModule(FileWatcherMixin):
    """The base class of all analysis logic.  All your custom analysis modules extend this class."""

    # When True (the default), valid_observable_types matching is subtype-aware:
    # a module declaring valid_observable_types = "email_address" will also
    # accept observables whose type extends email_address (e.g. "return_path").
    # Set False on a subclass that genuinely requires an exact type match.
    valid_observable_subtypes: bool = True

    def __init__(
        self,
        config: AnalysisModuleConfig,
        *args,
        context: Optional[AnalysisModuleContext] = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        assert isinstance(config, AnalysisModuleConfig), f"config must be an instance of AnalysisModuleConfig, got {type(config)}"

        # analysis module configuration (required)
        self.config = config

        # the instance defines the specific instance of the given analysis module
        # some analysis modules can have multiple instances
        # which are basically analysis modules that share the same python code but have different configurations
        # for example, a SplunkQueryAnalysisModule might have different instances for the different splunk searches
        # you might want to run
        # if this value is missing then it defaults to None, which is the "default" instance
        self._instance = config.instance

        # defaults to an empty context
        # this parameter is provided for ease of use in tests
        self._context = context or AnalysisModuleContext()

    def verify_environment(self):
        """Called after module is loaded to verify that everything it needs exists.."""
        pass

    def verify_path_exists(self, path):
        """Verifies the given path exists.  If the path is relative then it is relative to SAQ_HOME."""
        _path = path
        if not os.path.isabs(path):
            _path = os.path.join(get_base_dir(), path)

        if not os.path.exists(_path):
            raise RuntimeError("missing {} used by {}".format(path, self))

    def verify_program_exists(self, path):
        """Verifies the given program exists on the system.  If relative then $PATH is checked using which."""
        from subprocess import Popen, DEVNULL

        if os.path.isabs(path):
            if not os.path.exists(path):
                raise RuntimeError("missing {} used by {}".format(path, self))
        else:
            p = Popen(["which", path], stdout=DEVNULL, stderr=DEVNULL)
            p.wait()

            if p.returncode:
                raise RuntimeError("cannot find {} used by {}".format(path, self))

    def create_required_directory(self, dir):
        """Creates the given directory if it does not already exist.  Relative paths are relative to DATA_DIR."""

        if not os.path.isabs(dir):
            dir = os.path.join(get_data_dir(), dir)

        if os.path.isdir(dir):
            return

        try:
            logging.debug("creating required directory {}".format(dir))
            os.makedirs(dir)
        except Exception as e:
            if not os.path.isdir(dir):
                logging.error(
                    "unable to create required directory {} for {}: {}".format(
                        dir, self, e
                    )
                )
                raise e

    # ========================================
    # Configuration Properties
    # ========================================

    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return AnalysisModuleConfig

    @property
    def name(self) -> str:
        """Returns the name of the module."""
        return self.config.name

    @property
    def instance(self) -> Optional[str]:
        """Get the instance name from configuration."""
        # Return the instance passed to constructor, or fall back to config
        return self._instance if self._instance is not None else self.config.instance

    @property
    def priority(self) -> int:
        """Get the module priority (lower numbers = higher priority)."""
        return self.config.priority

    @property
    def observation_grouping_time_range(self) -> Optional[timedelta]:
        """Get the time range for grouping observations."""
        return self.config.observation_grouping_time_range

    @property
    def automation_limit(self) -> Optional[int]:
        """Get the automation limit for this module."""
        return self.config.automation_limit

    @property
    def maximum_analysis_time(self) -> int:
        """Get the maximum analysis time in seconds."""
        return self.config.maximum_analysis_time

    @property
    def observable_exclusions(self) -> dict:
        """Get the observable exclusions for this module."""
        return self.config.observable_exclusions

    @property
    def expected_observables(self) -> dict[str, set]:
        """Get the expected observables for this module."""
        return self.config.expected_observables

    @property
    def is_grouped_by_time(self):
        """Returns True if the observation_grouping_time_range configuration option is being used."""
        # if explicitly set, use that value
        if self.config.is_grouped_by_time:
            return True
        # otherwise, infer from observation_grouping_time_range being set
        return self.config.observation_grouping_time_range is not None

    @property
    def cooldown_period(self):
        """Number of seconds this module stays in cooldown state.  Defaults to 60."""
        return self.config.cooldown_period

    @property
    def semaphore_name(self):
        """The semaphore this module uses.  Defaults to None (no semaphore is used.)"""
        return self.config.semaphore_name

    @property
    def file_size_limit(self):
        """Returns the maximum size of a F_FILE type observable that this analysis module will accept.
        A value of 0 indicates no limit."""
        return self.config.file_size_limit

    @property
    def valid_observable_types(self) -> Union[str, list[str], None]:
        """Returns a single (or list of) Observable type that are valid for this module.
        If the configuration setting valid_observable_types is present then those values are used.
        Defaults to None (all types are valid.)  Return None to disable the check."""
        return self.config.valid_observable_types

    @property
    def valid_queues(self):
        """Returns a list of strings that are valid queues for this module.
        If the configuration setting valid_queues is present then those values are used.
        Defaults to None (all queues are valid.)  Return None to disable the check."""
        return self.config.valid_queues

    @property
    def invalid_queues(self):
        """Returns a list of strings that are invalid queues for this module.
        If the configuration setting invalid_queues is present then those values are used.
        Defaults to None (no queues are invalid)  Return None to disable the check."""
        return self.config.invalid_queues

    @property
    def invalid_alert_types(self):
        """Returns a list of strings that are invalid alert types for this module.
        If the configuration setting invalid_alert_types is present then those values are used.
        Defaults to None (no queues are invalid)  Return None to disable the check."""
        return self.config.invalid_alert_types

    @property
    def required_directives(self):
        """Returns a list of required directives for the analysis to occur.
        If the configuration setting required_directives is present, then those values are used.
        Defaults to an empty list."""
        return self.config.required_directives

    @property
    def required_tags(self):
        """Returns a list of required tags for the analysis to occur.
        If the configuration setting required_tags is present, then those values are used.
        Defaults to an empty list."""
        return self.config.required_tags

    @property
    def requires_detection_path(self) -> bool:
        """Returns True if this analysis module requires that the observable be on a detection path."""
        return self.config.requires_detection_path

    @property
    def allow_reanalysis_on_failure(self) -> bool:
        """Returns True if this analysis module allows re-analysis when the previous analysis failed.

        When True, if an observable already has a completed analysis from this module
        but that analysis failed (Analysis.error is set), the module will be allowed
        to run again (the failed analysis will be removed first).

        Override this property in subclasses to enable retry behavior.
        Defaults to False.
        """
        return False

    @property
    def version(self):
        """Returns the module version for cache validation."""
        return self.config.version

    @property
    def cache_ttl(self) -> Optional[timedelta]:
        """Returns the cache TTL for this module. None disables caching."""
        return self.config.cache_ttl

    @property
    def extended_version(self) -> dict[str, str]:
        """Dynamic inputs to mix into the cache key.

        Override in subclasses that depend on external state (rules files, feed
        versions, model weights, etc.) so the cache key invalidates when those
        change. Default: empty dict.
        """
        return {}

    @property
    def shutdown(self):
        """Returns True if the current analysis engine is shutting down, False otherwise."""
        return self._context.shutdown

    @property
    def controlled_shutdown(self):
        """Returns True if the current analysis engine is shutting down when complete."""
        return self._context.controlled_shutdown

    @property
    def generated_analysis_type(self) -> Optional[Type[Analysis]]:
        """Returns the type of the Analysis-based class this AnalysisModule generates.
        Returns None if this AnalysisModule does not generate an Analysis object."""
        return None

    @property
    def maintenance_frequency(self):
        """Returns how often to execute the maintenance function, in seconds, or None to disable (the default.)"""
        return None

    # ========================================
    # Context and Dependency Injection
    # ========================================

    def set_context(self, context: AnalysisModuleContext):
        """Set the analysis context for dependency injection."""
        self._context = context

    def set_analysis_deadline(self, deadline: Optional[float]):
        """Called by the engine around each call to analyze(), with the time.monotonic() value
        past which the engine stops that call, or None once it has returned."""
        self._context.analysis_deadline = deadline

    def time_left(self) -> float:
        """Returns how many seconds the current call to analyze() has before the engine stops it:
        either the worker is killed for exceeding the module's maximum_analysis_time, or the rest
        of the root's pass is abandoned for exceeding the mode's cumulative fail time. Negative
        once the deadline has passed. Outside of an engine call (a unit test, the GUI) this is the
        module's maximum_analysis_time."""
        if self._context.analysis_deadline is None:
            return float(self.maximum_analysis_time)

        return self._context.analysis_deadline - time.monotonic()

    def run_tool(self, args: list[str], target: str, *, timeout: Optional[float] = None,
                 **kwargs) -> Optional[subprocess.CompletedProcess]:
        """Runs an external tool on target as subprocess.run(args, **kwargs) does and returns its
        CompletedProcess, or None if it had to be stopped: a tool still running after timeout
        seconds, or TOOL_TIMEOUT_MARGIN_SECONDS before this call to analyze() runs out of time, is
        killed, where it would otherwise run until the engine kills the worker."""
        allowed = max(1.0, self.time_left() - TOOL_TIMEOUT_MARGIN_SECONDS)
        timeout = allowed if timeout is None else max(1.0, min(timeout, allowed))
        try:
            return subprocess.run(args, timeout=timeout, **kwargs)
        except subprocess.TimeoutExpired:
            logging.warning("%s stopped %s on %s after %.0f seconds", self, args[0], target, timeout)
            return None

    def run_sandboxed_tool(
        self,
        args: list[str],
        target: str,
        *,
        timeout: Optional[float] = None,
        read_files: Sequence[str] = (),
        read_dirs: Sequence[str] = (),
        write_dirs: Sequence[str] = (),
        outputs: Optional[dict[str, str]] = None,
        cwd: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
        memory_limit: Optional[int] = None,
        startup_errors: Sequence[str] = (),
        partial_output: bool = False,
    ) -> Optional[SandboxResult]:
        """Runs an external tool on target, a file from the alert, in the Landlock sandbox
        (docs/TOOL_SANDBOX.md), and returns what it did; None if it was stopped or could not run.

        The tool can read target, read_files and read_dirs, and the directory its program is in, and
        write only its own empty working directory (its cwd, HOME and TMPDIR, unless cwd names one of
        write_dirs) and write_dirs, which the module creates for it; no network. A name in args
        without a directory is relative to the working directory, and an arg that is target or one of
        read_files or write_dirs is made absolute (one inside a longer arg, like 7z's -o<dir>, is the
        module's to make absolute). outputs maps names relative to the working directory to where
        the module keeps them, and each one the tool left as a plain file is moved there once it has
        finished, whatever its exit status. Nothing is moved from a tool that was stopped.

        It is stopped like run_tool() stops one (at timeout seconds, or before this call to analyze()
        runs out of time), when it writes more than tool_sandbox.max_output_bytes, and when
        should_stop() says so. env is added to the tool's environment, which is never ACE's own.
        memory_limit replaces tool_sandbox.memory_limit for a runtime that reserves more address
        space than it uses. startup_errors are what such a runtime starts its stdout or stderr with
        when the sandbox keeps it from starting (a directory it needs is not readable, the memory
        limit is too small for it): a non-zero exit that starts so is reported like a program the
        sandbox cannot start. With partial_output, a tool stopped for writing too much output returns
        what it wrote up to then, flagged output_exceeded, rather than None; it keeps no outputs."""
        config = get_config().tool_sandbox
        if memory_limit is not None:
            config = config.model_copy(update={"memory_limit": memory_limit})
        program = self._resolve_tool(args[0])
        if program is None:
            self._sandbox_failed(args[0], target, f"{args[0]} not found")
            return None

        try:
            tool_dirs = _tool_dirs(program)
        except ValueError as e:
            self._sandbox_failed(program, target, str(e))
            return None

        available = landlock_available()
        if available is None:
            # landlock_available() reported why with its traceback; the next call probes again, so
            # this says nothing about the node, and a later failure of the tool is still reported
            logging.warning("%s did not run %s on %s: the Landlock probe could not run", self, os.path.basename(program),
                            target, extra={"path": target})
            return None
        if not available:
            self._sandbox_failed(program, target, "the Landlock sandbox is not available on this node")
            return None

        # ACE's paths are often relative to SAQ_HOME, the tool's are relative to its working directory
        absolute = {path: os.path.abspath(path) for path in [target, *read_files, *write_dirs]}
        args = [absolute.get(arg, arg) for arg in args]
        target = absolute[target]

        allowed = max(1.0, self.time_left() - TOOL_TIMEOUT_MARGIN_SECONDS)
        seconds = allowed if timeout is None else max(1.0, min(timeout, allowed))
        tool = os.path.basename(program)
        work_root = os.path.abspath(os.path.join(get_data_dir(), config.work_dir))
        _sweep_tool_workdirs(work_root)
        with create_workdir(work_root) as workdir:
            argv = build_sandbox_argv(
                [program, *args[1:]], workdir, config, timedelta(seconds=seconds),
                read_files=[path for path in (target, *(absolute[path] for path in read_files)) if os.path.exists(path)],
                read_dirs=[*tool_dirs, *read_dirs],
                write_dirs=[absolute[path] for path in write_dirs],
                # RLIMIT_CPU counts every thread, and john, 7z and the JVM run one per core; the
                # timeout still bounds the wall time
                cpu_seconds=math.ceil(seconds * (os.cpu_count() or 1)),
            )
            # never os.environ: Landlock does not filter the environment and ACE's carries secrets
            tool_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "HOME": workdir,
                        "TMPDIR": workdir, **(env or {})}
            try:
                result = run_sandboxed(argv, None, tool_env, os.path.abspath(cwd) if cwd else workdir,
                                       timedelta(seconds=seconds), config.max_output_bytes, cancel=self.should_stop)
            except SandboxCancelled:
                logging.info("%s stopped %s on %s: the analysis was stopped", self, tool, target,
                             extra={"path": target})
                return None
            except SandboxOutputExceeded as e:
                # the file's doing, not the node's
                logging.warning("%s stopped %s on %s: %s", self, tool, target, e, extra={"path": target})
                return e.result if partial_output else None
            except RuntimeError as e:
                # a timeout: the file's doing, not the node's
                logging.warning("%s stopped %s on %s: %s", self, tool, target, e, extra={"path": target})
                return None

            # a program the sandbox cannot start: a wrong path, or a directory it needs that is not readable
            if not result.stdout.strip() and result.returncode in NODE_FAILURE_EXIT_CODES:
                self._sandbox_failed(program, target, result.stderr.strip()[-500:])
                return None

            # the start of the output, which the file it analyzes does not decide
            if result.returncode != 0 and any(output.lstrip().startswith(error) for error in startup_errors
                                              for output in (result.stdout, result.stderr)):
                self._sandbox_failed(program, target, (result.stdout.strip() or result.stderr.strip())[:500])
                return None

            # SIGXFSZ: what it was writing is cut off at the limit, and it wrote nothing after that.
            # The file's doing, like a timeout
            if result.returncode == 128 + signal.SIGXFSZ:
                logging.warning("%s stopped %s on %s: it wrote a file larger than tool_sandbox's file size limit "
                                "of %d bytes", self, tool, target, config.file_size_limit, extra={"path": target})
                return None

            for name, destination in (outputs or {}).items():
                if not _keep_tool_output(os.path.join(workdir, name), destination):
                    logging.warning("%s did not keep %s's output %s on %s: not a plain file", self, tool, name, target,
                                    extra={"path": target})

        return result

    def _resolve_tool(self, name: str) -> Optional[str]:
        """The absolute path of the program a tool runs, found the way Popen would find it."""
        if os.sep not in name:
            return shutil.which(name)

        path = name if os.path.isabs(name) else os.path.join(get_base_dir(), name)
        return path if os.access(path, os.X_OK) else None

    def _sandbox_failed(self, program: str, target: str, reason: str):
        """A tool this node cannot run in the sandbox is an operator's problem, reported once per process."""
        key = f"{self.config.name}:{program}"
        message = f"{self} cannot run {program} in the sandbox: {reason}"
        if key in _REPORTED_SANDBOX_FAILURES:
            logging.warning("%s (on %s)", message, target, extra={"path": target})
            return

        _REPORTED_SANDBOX_FAILURES.add(key)
        logging.error("%s (on %s)", message, target, exc_info=RuntimeError(message), extra={"path": target})

    def get_root(self) -> RootAnalysisInterface:
        """Get the root analysis interface from the dependency injection context."""
        if self._context is None:
            raise RuntimeError(
                "No context available - AnalysisModule must be created with an AnalysisContext"
            )
        return self._context.root

    def _get_state_repository(self):
        """Get the state repository from the context, falling back to creating one if needed."""
        if self._context is None:
            raise RuntimeError(
                "No context available - AnalysisModule must be created with an AnalysisContext"
            )
        
        # If no state repository is provided in context, create a default one using root analysis
        if self._context.state_repository is None:
            from saq.modules.state_repository import StateRepositoryFactory
            self._context.state_repository = StateRepositoryFactory.create_root_analysis_repository(
                self.get_root()
            )
        
        return self._context.state_repository

    # ========================================
    # State Management
    # ========================================

    @property
    def state(self):
        """Returns the dict object you can use to maintain state over time."""
        state_repository = self._get_state_repository()
        return state_repository.get_state(self.name)

    @state.setter
    def state(self, value):
        state_repository = self._get_state_repository()
        state_repository.set_state(self.name, value)

    def initialize_state(self, value={}):
        """Sets the state for this module to the given value (defaults to empty dict.)
        If the state is already set this function does nothing."""
        state_repository = self._get_state_repository()
        state_repository.initialize_state(self.name, value)

    # ========================================
    # Analysis Target Validation
    # ========================================

    def is_excluded(self, observable: Observable) -> bool:
        """Returns True if the given observable is excluded from analysis for this module."""
        if observable.type not in self.observable_exclusions:
            return False

        for exclusion_value in self.observable_exclusions[observable.type]:
            if observable.matches(exclusion_value):
                return True

        return False

    def is_expected_observable(self, o_type, o_value):
        """Returns True if the given observable is an expected observable for this module."""
        try:
            return o_value in self.expected_observables[o_type]
        except KeyError:
            logging.debug("o_type {} not in {}".format(o_type, self))
            return False

    def custom_requirement(self, observable: Observable) -> bool:
        """Optional function is called as an additional check to see if this observable should be
        analyzed by this module. Returns True if it should be *considered* for analysis, False if not.
        If this function is not overridden then it is ignored."""
        raise NotImplementedError()

    def should_analyze(self, observable: Observable) -> bool:
        """Put your custom "should I analyze this?" logic in this function."""
        return True

    def accepts(self, observable: Observable) -> bool:
        """Returns True if this observable should be analyzed by this module, False otherwise."""

        # we still call execution on the module in cooldown mode
        # there may be things it can (or should) do while on cooldown

        # if this analysis module does not generate analysis then we can skip this
        # these are typically analysis modules that only do pre or post analysis work
        if self.generated_analysis_type is None:
            return False

        # does this analysis module require that the observable be on a detection path?
        if self.requires_detection_path:
            if not observable.is_on_detection_path():
                logging.debug(
                    "module %s requires %s be on a detection path", self.name, observable
                )
                return False

        if self.valid_observable_types is not None:
            # a little hack to allow valid_observable_types to return a single value
            valid_types = self.valid_observable_types
            if isinstance(valid_types, str):
                valid_types = [valid_types]

            try:
                if self.valid_observable_subtypes:
                    hierarchy = get_type_hierarchy()
                    if not any(
                        hierarchy.is_subtype(observable.type, vt) for vt in valid_types
                    ):
                        return False
                else:
                    if observable.type not in valid_types:
                        return False
            except Exception:
                logging.exception(
                    "valid_observable_types returned invalid data type {} for {}".format(
                        type(valid_types), self
                    )
                )
                return False

        # do not accept observables from queues we are not configured to accept
        if self.valid_queues is not None:
            root = self.get_root()
            if hasattr(root, "queue") and root.queue not in self.valid_queues:
                return False

        # do not accept observables from queues we are configured to ignore
        if self.invalid_queues is not None:
            root = self.get_root()
            if hasattr(root, "queue") and root.queue in self.invalid_queues:
                return False

        # are we ignoring this observable for this analysis module because of the alert type?
        if self.invalid_alert_types is not None:
            root = self.get_root()
            if (
                hasattr(root, "alert_type")
                and root.alert_type in self.invalid_alert_types
            ):
                return False

        # has this observable been marked to skip all analysis? this mirrors
        # the check in the engine's _process_observable_exclusions so a
        # directive added mid-work-item (e.g. by the observable modifier)
        # immediately gates the remaining modules in the same pass.
        if observable.has_directive(DIRECTIVE_EXCLUDE_ALL):
            return False

        # does this analysis module exclude this observable from analysis?
        if self.is_excluded(observable):
            # logging.debug("observable {} is excluded from analysis by {}".format(observable, self))
            return False

        # does this observable exclude itself from this kind of analysis?
        if observable.is_excluded(self):
            # logging.debug("analysis module {} excluded from analyzing {}".format(self, observable))
            return False

        # does this analysis module require directives?
        for directive in self.required_directives:
            if not observable.has_directive(directive):
                # logging.debug("{} does not have required directive {} for {}".format(observable, directive, self))
                return False

        # does this analysis module require tags?
        for tag in self.required_tags:
            if not observable.has_tag(tag):
                # logging.debug("{} does not have required directive {} for {}".format(observable, directive, self))
                return False

        # NOTE custom_requirement is intentionally NOT evaluated here. it is
        # evaluated by the engine as the final gate right before the module runs
        # (after declared dependencies are satisfied) so that it can inspect
        # dependency results and wait on cross-observable analysis. see
        # AnalysisExecutor._execute_module_analysis.

        # have we already generated analysis for this target?
        current_analysis = observable.get_analysis(
            self.generated_analysis_type, instance=self.instance
        )
        if current_analysis is not None:
            # did it return nothing?
            if isinstance(current_analysis, bool) and not current_analysis:
                logging.debug(
                    "already analyzed {} with {} and returned nothing".format(
                        observable, self
                    )
                )
                return False

            # has this analysis completed?
            if current_analysis.completed:
                if self.allow_reanalysis_on_failure and current_analysis.error is not None:
                    # Remove the failed analysis to allow retry
                    logging.info(
                        f"removing failed analysis {current_analysis} from {observable} "
                        f"to allow retry by {self}"
                    )
                    module_path = current_analysis.module_path
                    if module_path in observable.analysis:
                        del observable.analysis[module_path]
                    # Continue - don't return False, allow reanalysis
                else:
                    logging.debug("already analyzed {} with {}".format(observable, self))
                    return False

        # is this observable a file and do we have a file size limit for this module?
        if observable.type == F_FILE and self.file_size_limit > 0:
            try:
                target_path = observable.full_path
                if os.path.exists(target_path):
                    if observable.size > self.file_size_limit:
                        logging.debug(
                            f"{target_path} exceeds file size limit {self.file_size_limit} for {self}"
                        )
                        return False
            except Exception as e:
                logging.warning(f"unable to get size of file {observable.file_path} for {self}: {e}")

        # are we in cooldown mode?
        # XXX side effect!
        if self._context.cooldown_timeout:
            # are we still in cooldown mode?
            if datetime.now() < self._context.cooldown_timeout:
                logging.debug("{} in cooldown mode".format(self))
            else:
                self._context.cooldown_timeout = None
                logging.info("{} exited cooldown mode".format(self))

        # does this module have automation limits?
        if self.automation_limit is not None:
            # and is this observable NOT ignoring automation limits?
            # this can be the case if an analyst is forcing analysis of something
            if not observable.has_directive(DIRECTIVE_IGNORE_AUTOMATION_LIMITS):
                # how many times have we already generated analysis with this module?
                current_analysis_count = len(
                    self.get_root().get_analysis_by_type(self.generated_analysis_type)
                )
                if current_analysis_count >= self.automation_limit:
                    logging.debug(
                        f"{self} reached automation limit of {self.automation_limit} for {self.get_root()}"
                    )
                    return False

        # end with custom logic, which defaults to True if not implemented
        return self.should_analyze(observable)

    # ========================================
    # Analysis Lifecycle
    # ========================================

    def create_analysis(self, observable: Observable) -> Analysis:
        """Initializes and adds the generated Analysis for this module to the given Observable.
        Returns the generated Analysis."""
        # have we already created analysis for this observable?
        if self.generated_analysis_type is None:
            raise RuntimeError(f"called create_analysis on {self} which does not actually create Analysis")

        analysis = observable.get_analysis(
            self.generated_analysis_type, instance=self.instance
        )
        if analysis:
            logging.debug(
                "returning existing analysis {} in call to create analysis from {} for {}".format(
                    analysis, self, observable
                )
            )
            return analysis

        # otherwise we create and initialize a new one
        analysis = self.generated_analysis_type()
        analysis.instance = self.instance
        observable.add_analysis(analysis)
        # this is where initialize_details was called
        return analysis

    def wait_for_analysis(self, observable, analysis_type, instance=None):
        """Waits for the given Analysis (by type) be available for the given Observable."""
        from saq.engine.errors import WaitForAnalysisException

        assert isinstance(observable, Observable)
        assert inspect.isclass(analysis_type) and issubclass(analysis_type, Analysis)
        assert instance is None or isinstance(instance, str)

        # do we already have a dependency here?
        dep = observable.get_dependency(MODULE_PATH(analysis_type, instance=instance))

        # have we already analyzed this observable for this analysis type?
        analysis = observable.get_analysis(analysis_type, instance=instance)

        # if the dependency has been completed or resolved then we just return whatever we got
        # even if it was nothing
        if dep and (dep.completed or dep.resolved or dep.failed):
            if isinstance(analysis, Analysis):
                analysis.load_details()
            return analysis

        # if we haven't analyzed this yet or we have and it hasn't completed yet (delayed) then we wait
        if (
            analysis is None
            or isinstance(analysis, Analysis)
            and not analysis.completed
        ):
            raise WaitForAnalysisException(observable, analysis_type, instance=instance)

        # otherwise we return the analysis
        if isinstance(analysis, Analysis):
            analysis.load_details()

        return analysis

    def analyze(self, observable: Observable, final_analysis: bool=False, delayed_analysis: bool=False) -> AnalysisExecutionResult:
        """Called by an analysis engine to analyze a given Observable."""

        assert isinstance(observable, Observable)
        logging.debug(f"analyzing {observable} with {self} (final analysis={final_analysis}, delayed analysis={delayed_analysis})")

        # if we're watching any files, see if they've changed and need to be reloaded
        self.check_watched_files()

        if self.analysis_covered(observable):
            logging.debug(f"{observable} is already covered by another {self} analysis")
            return AnalysisExecutionResult.COMPLETED

        analysis_result = AnalysisExecutionResult.COMPLETED

        try:
            # if we are executing in "final analysis mode" then we call this function instead
            if final_analysis:
                analysis_result = self.execute_final_analysis(observable)
            # are we continuing analysis of a delayed analysis?
            elif delayed_analysis:
                # get the analysis that has been completed so far
                existing_analysis = observable.get_and_load_analysis(self.generated_analysis_type, instance=self.instance)
                if existing_analysis:
                    analysis_result = self.continue_analysis(observable, existing_analysis)
                else:
                    analysis_result = self.execute_analysis(observable)
            else:
                analysis_result = self.execute_analysis(observable)
        except AnalysisError as e:
            # the module said it failed: the analyst sees why on its analysis, which is kept with
            # whatever the module put in it before it failed
            close_with_error(self.create_analysis(observable), e.message)
            # at INFO, so no error report: the failure was expected. the traceback of the exception it
            # wraps, if any, is still the only way to find its cause from the log
            logging.info(
                "%s failed to analyze %s: %s", self, observable, e.message,
                exc_info=e.__cause__ or e.__context__,
                extra={
                    "module_name": self.name,
                    "observable_uuid": observable.uuid,
                    "observable_type": observable.type,
                    "root_uuid": self.get_root().uuid,
                    "analysis_error": e.message,
                },
            )
            return AnalysisExecutionResult.COMPLETED

        if not isinstance(analysis_result, AnalysisExecutionResult):
            logging.error(f"analysis module {self} should return an AnalysisExecutionResult (returned {type(analysis_result)})")
            return analysis_result

        # if we are grouping by time then we mark this Observable as a future target for other grouping
        # (if we got an analysis result)
        if analysis_result == AnalysisExecutionResult.COMPLETED and self.is_grouped_by_time:
            observable.grouping_target = True

        return analysis_result

    def delay_analysis(
        self,
        observable: Observable,
        analysis: Analysis,
        hours: Optional[int]=None,
        minutes: Optional[int]=None,
        seconds: Optional[int]=None,
        timeout_hours: Optional[int]=None,
        timeout_minutes: Optional[int]=None,
        timeout_seconds: Optional[int]=None,
    ) -> AnalysisExecutionResult:
        """Called to delay this analysis until the specified amount of time has expired."""
        assert isinstance(observable, Observable)
        assert isinstance(analysis, Analysis)

        if hours is None and minutes is None and seconds is None:
            hours = 0
            minutes = 0
            seconds = 10

        if hours is None:
            hours = 0

        if minutes is None:
            minutes = 0

        if seconds is None:
            seconds = 0

        root = self.get_root()

        logging.debug(
            "adding delayed analysis for "
            "{} by {} on {} analysis {} hours {} minutes {} seconds {}".format(
                root, self, observable, analysis, hours, minutes, seconds
            )
        )

        # For backwards compatibility, we need to pass the actual objects, not the adapters
        # TODO: Eventually engine.delay_analysis should also be abstracted
        root_obj = root._root if hasattr(root, "_root") else root
        # XXX obviously this is a bad design, but it's a quick fix for now
        from saq.modules.adapter import AnalysisModuleAdapter

        if self._context.delayed_analysis_interface.delay_analysis(
            root_obj,
            observable,
            analysis,
            AnalysisModuleAdapter(self),
            hours=hours,
            minutes=minutes,
            seconds=seconds,
            timeout_hours=timeout_hours,
            timeout_minutes=timeout_minutes,
            timeout_seconds=timeout_seconds,
        ):
            analysis.completed = False
            analysis.delayed = True
            return AnalysisExecutionResult.INCOMPLETE

        # the delay was refused (deadline expired): the analysis is closed out WITHOUT the module
        # ever receiving its result, which is a failure the analyst sees, and is never cached
        close_with_error(analysis, "timed out waiting for delayed analysis to complete")
        return AnalysisExecutionResult.COMPLETED

    # ========================================
    # Core Analysis Execution
    # ========================================

    def execute_pre_analysis(self):
        """This is called once at the very beginning of analysis."""
        pass

    def execute_analysis(self, observable: Observable) -> AnalysisExecutionResult:
        """Called to analyze an Observable. Override this in your subclass.
        Return COMPLETED if analysis has completed. The engine will not call this function again for this target.
        Return INCOMPLETE if analysis has NOT completed. The engine will call this function again for this target.
        """
        raise NotImplementedError()

    def continue_analysis(self, observable: Observable, analysis: Analysis) -> AnalysisExecutionResult:
        """Called to continue analysis of an Observable object after delay_analysis has been called."""
        raise NotImplementedError()

    def execute_final_analysis(self, observable: Observable) -> AnalysisExecutionResult:
        """Called to analyze an Observable after all other analysis has completed.
        Return COMPLETED if analysis has completed. The engine will not call this function again for this target.
        Return INCOMPLETE if analysis has NOT completed. The engine will call this function again for this target.
        """
        return AnalysisExecutionResult.COMPLETED

    def execute_post_analysis(self) -> AnalysisExecutionResult:
        """Called at the end of every analysis pass over the root that leaves no delayed analysis
        outstanding: the first pass, every analysis mode change, every disposition, analyst requested
        analysis and after an analysis timeout. It must therefore be idempotent.

        The return value (COMPLETED or INCOMPLETE) is recorded in root.state["post_analysis_executed"]
        for diagnostics only; it does not stop the engine calling this again on a later pass."""
        return AnalysisExecutionResult.COMPLETED

    def on_cache_hit(self, root: RootAnalysisInterface, observable: Observable) -> None:
        """Called after a cached analysis has been replayed for this module, in place
        of execute_analysis. Default is a no-op; override to emit hit-time telemetry
        from the replayed analysis (available via observable.get_analysis)."""
        pass

    # ========================================
    # Analysis Helpers
    # ========================================

    def get_analysis(self, observable):
        for analysis in observable.all_analysis:
            if isinstance(analysis, self.generated_analysis_type):
                return analysis
        return None

    def analysis_covered(self, observable):
        """Returns True if the value of this observable has already been analyzed in another observable
        that has an observation time with range of this observable."""

        # for this to have any meaning, the observations must have correponding times
        if not observable.time:
            return False

        # is this feature enabled for this analysis module?
        if not self.is_grouped_by_time:
            return False

        # must have a timezone
        if observable.time.tzinfo is None:
            return False

        start_time = observable.time - self.observation_grouping_time_range
        end_time = observable.time + self.observation_grouping_time_range

        grouping_target_available = False

        # NOTE that we also iterate over the observable we're looking at
        for target_observable in self.get_root().get_observables_by_type(
            observable.type
        ):

            if target_observable.value != observable.value:
                continue

            # does this target observables time fall in the range we're looking for?
            if target_observable.time is None:
                continue

            # must have a timezone
            if target_observable.time.tzinfo is None:
                continue

            if (
                target_observable.time >= start_time
                and target_observable.time <= end_time
            ):
                # does this target_observable already have this analysis generated?
                if target_observable.get_analysis(
                    self.generated_analysis_type, instance=self.instance
                ):
                    logging.debug(
                        f"{target_observable} already has analysis for "
                        f"{self.generated_analysis_type} between times {start_time} and {end_time} "
                        f"{observable}"
                    )
                    return True

                # this target is in range AND is already a grouping target
                # NOTE that we want to keep looking for existing analysis so we don't break out of the loop here
                if target_observable.grouping_target:
                    logging.debug(
                        f"{target_observable} detected as grouping target for "
                        f"{self.generated_analysis_type} {observable}"
                    )
                    grouping_target_available = True

        # if we didn't find anything and the observable we're looking at is a grouping target then this is
        # the one we want to analyze
        if observable.grouping_target:
            logging.debug(
                f"using {observable} as grouping target for {self.generated_analysis_type}"
            )
            return False

        # if we didn't find anything but we did find another observable in the group that is already a grouping
        # target then we are considered "covered" because *that* observable will get the analysis
        if grouping_target_available:
            return True

        # otherwise we analyze this one
        return False

    # ========================================
    # Cancellation and Control
    # ========================================

    def cancel_analysis(self):
        """Try to cancel the analysis loop."""
        self._context.cancel_analysis_flag = True

        # execute any custom handlers defined by the engine
        self.cancel_analysis_handler()

    def is_canceled_analysis(self) -> bool:
        """Returns True if the current analysis has been canceled, by this module or by the engine."""
        return self._context.cancel_analysis_flag or self._context.engine_canceled

    def should_stop(self) -> bool:
        """Returns True if the module should abandon what it is doing: the engine is shutting down
        or the analysis was cancelled. Pass it as the cancel of a blocking call (run_sandboxed)."""
        return self.shutdown or self.is_canceled_analysis()

    def cancel_analysis_handler(self):
        """Override this function to implement custom cancel code."""
        pass

    def enter_cooldown(self):
        """Puts this module into cooldown mode which will cause it to get skipped for self.cooldown_period seconds."""
        self._context.cooldown_timeout = datetime.now() + timedelta(
            seconds=self.cooldown_period
        )
        logging.warning(
            "{} entered cooldown period until {}".format(
                self, self._context.cooldown_timeout
            )
        )

    # ========================================
    # Maintenance and Utilities
    # ========================================

    def sleep(self, seconds):
        """Utility function to sleep for N seconds without blocking shutdown."""
        while not self.should_stop() and seconds > 0:
            # we also want to support sleeping for less than a second
            time.sleep(min(1, seconds))
            seconds -= 1

    def auto_reload(self):
        """Called every N seconds (see auto_reload_frequency in abstract
        engine) in the main process to allow the module to update or change
        configuration."""
        return

    def execute_maintenance(self):
        """Override this function to provide some kind of maintenance routine that is called every
        maintenance_frequency seconds."""
        pass

    def cleanup(self):
        """Called after all analysis has completed. Override this if you need to clean up something after analysis."""
        pass

    # ========================================
    # Utility Methods
    # ========================================

    def get_module_path(self) -> str:
        return MODULE_PATH(self)

    def __str__(self):
        result = type(self).__name__
        if self.instance is not None:
            result += f":{self.instance}"

        return result
