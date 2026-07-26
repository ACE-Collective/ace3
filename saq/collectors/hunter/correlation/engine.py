import datetime
import logging
import tempfile
import time
from dataclasses import dataclass, field
from typing import Optional

from jinja2.sandbox import SandboxedEnvironment

from saq.collectors.hunter.correlation.actions import ActionResult, execute_action
from saq.collectors.hunter.correlation.cache import CorrelateQueryRecorder
from saq.collectors.hunter.correlation.commands import _resolve_time_range, execute_command
from saq.configuration.config import get_config
from saq.configuration.encryption import export_encrypted_passwords
from saq.collectors.hunter.correlation.expressions import build_jinja_context, evaluate_expression_traced
from saq.collectors.hunter.correlation.registry import get_query_source
from saq.collectors.hunter.correlation.schema import (
    ActionConfig,
    CommandConfig,
    ConditionConfig,
    CorrelateConfig,
    PredefinedCommandConfig,
    StepConfig,
    TransformConfig,
)
from saq.collectors.hunter.correlation.timespec import parse_timespec
from saq.collectors.hunter.correlation.trace import (
    ActionTrace,
    ConditionTrace,
    CorrelationTrace,
    EventTrace,
    StepTrace,
    StreamEvent,
    TransformTrace,
    sanitize_value,
)
from saq.collectors.hunter.correlation.transforms import apply_transform

_jinja_env = SandboxedEnvironment()

_MAX_REPR_LENGTH = 200


def _truncate_repr(value) -> str:
    """Return a truncated string representation of a value for tracing."""
    s = repr(value)
    if len(s) > _MAX_REPR_LENGTH:
        return s[:_MAX_REPR_LENGTH] + "..."
    return s


class _StreamReset(Exception):
    """Internal signal that a stream transform occurred."""
    def __init__(self, new_stream: list[dict], resume_step_index: int):
        self.new_stream = new_stream
        self.resume_step_index = resume_step_index


class _StepError(Exception):
    """Internal signal that a step failed. The affected event short-circuits
    further step processing and is routed to alert. The caller is responsible
    for appending step_trace to the parent trace list before the exception
    propagates, so the failing step is visible in the event trace."""
    def __init__(self, message: str, step_trace: "StepTrace"):
        super().__init__(message)
        self.step_trace = step_trace


@dataclass
class CorrelationResult:
    """Result of running correlation on an event stream."""
    events: list[dict] = field(default_factory=list)
    event_actions: dict[int, ActionResult] = field(default_factory=dict)
    discarded: bool = False
    trace: Optional[CorrelationTrace] = None
    # keeps track of the index of the event from the original stream that produced each kept event.
    # Lets callers map a post-correlation event back to its EventTrace.event_index.
    alert_event_origin_indices: list[int] = field(default_factory=list)
    # rendered query results captured during this run, as [{source, query, results}].
    # lets the validator save correlate query results for offline replay.
    captured_queries: list[dict] = field(default_factory=list)


class CorrelationEngine:
    """Main correlation engine that orchestrates expressions, transforms, and actions."""

    def __init__(
        self,
        correlate_config: CorrelateConfig,
        predefined_commands: list[PredefinedCommandConfig],
        hunt_start_time: datetime.datetime,
        hunt_end_time: Optional[datetime.datetime] = None,
        max_result_count: Optional[int] = None,
        hunt_source_type: Optional[str] = None,
        correlate_replay: Optional[list[dict]] = None,
        hunt_name: Optional[str] = None,
        hunt_uuid: Optional[str] = None,
    ):
        self.config = correlate_config
        self.predefined_commands = predefined_commands or []
        self.hunt_name = hunt_name
        self.hunt_uuid = hunt_uuid
        # the hunt's query window. stream transforms (and event transforms with no
        # resolvable per-event time field) anchor their relative time_range to it:
        # `before` extends before hunt_start_time, `after` extends after hunt_end_time.
        # hunt_end_time defaults to hunt_start_time (a zero-width window) so callers
        # that don't have a range behave as a single reference point.
        self.hunt_start_time = hunt_start_time
        self.hunt_end_time = hunt_end_time if hunt_end_time is not None else hunt_start_time
        self.max_result_count = max_result_count
        self.timeout = parse_timespec(correlate_config.timeout)
        self.stream_query_cache: dict[str, str] = {}
        # captures (and optionally replays) rendered query results so the validator
        # can save correlate queries for fast offline iteration. when seeded with
        # `correlate_replay`, matching queries return saved results instead of
        # hitting the data source.
        self.query_recorder = CorrelateQueryRecorder(replay=correlate_replay)
        # name of the source that produced the current event stream; starts as the
        # hunt's primary type (e.g. "splunk") and updates when a stream-mutate query
        # command replaces the stream from a different source. used to supply
        # default relative_time_field/format when the YAML omits them.
        self.hunt_source_type = hunt_source_type
        self._current_source: Optional[str] = hunt_source_type

    def execute(self, events: list[dict]) -> CorrelationResult:
        """Execute correlation logic on the event stream."""
        # reset source tracking so a reused engine instance starts from the hunt's primary type
        self._current_source = self.hunt_source_type

        # Fetch secrets and config once per execution
        try:
            self._secrets = export_encrypted_passwords()
        except Exception:
            logging.error("unable to load secrets for correlation context", exc_info=True)
            self._secrets = {}

        try:
            self._config = get_config().raw._data
        except Exception:
            logging.error("unable to load config for correlation context", exc_info=True)
            self._config = {}

        result = CorrelationResult()
        trace = CorrelationTrace()
        start_time = datetime.datetime.now(datetime.timezone.utc)
        alert_events = []
        event_index = 0
        # When a stream transform resets the stream, we skip steps before this index
        start_step_index = 0

        while event_index < len(events):
            elapsed = datetime.datetime.now(datetime.timezone.utc) - start_time
            if elapsed >= self.timeout:
                logging.warning(
                    "correlation timeout reached after %s for %s, remaining events will fall through to alert",
                    elapsed, self._hunt_label(),
                )
                trace.stream_events.append(StreamEvent(
                    event_type="timeout",
                    at_event_index=event_index,
                    detail=f"timeout after {elapsed}",
                ))
                for i in range(event_index, len(events)):
                    alert_events.append((i, events[i]))
                    result.event_actions[i] = ActionResult(action_type="alert")
                    trace.event_traces.append(EventTrace(event_index=i, outcome="timeout"))
                break

            event = events[event_index]
            event_trace = EventTrace(event_index=event_index)

            event_t0 = time.perf_counter()
            try:
                action_result = self._process_event_steps(
                    self.config.logic, event, events, event_index, start_time,
                    start_step_index, event_trace.steps,
                )
            except _StreamReset as sr:
                trace.stream_events.append(StreamEvent(
                    event_type="stream_reset",
                    at_event_index=event_index,
                    detail=f"stream reset to {len(sr.new_stream)} events, resuming at step {sr.resume_step_index}",
                ))
                events = sr.new_stream
                event_index = 0
                start_step_index = sr.resume_step_index
                # Clear accumulated alerts since stream changed
                alert_events = []
                result.event_actions = {}
                # Prior per-event traces ran against the now-replaced stream, so
                # drop them — but keep the trace that triggered the reset. Its
                # steps hold the stream transform's rendered command and result
                # count, the only record of what the transform actually did.
                event_trace.outcome = "stream_reset"
                trace.event_traces = [event_trace]
                continue
            except _StepError:
                # A step raised an error. Short-circuit further step processing
                # for this event and route it to alert. The failing step's trace
                # has already been appended to event_trace.steps by the caller.
                event_trace.outcome = "error"
                alert_events.append((event_index, event))
                result.event_actions[event_index] = ActionResult(action_type="alert")
                trace.event_traces.append(event_trace)
                event_index += 1
                continue
            finally:
                event_trace.duration_ms = (time.perf_counter() - event_t0) * 1000.0

            if action_result is None:
                action_result = ActionResult(action_type="alert")

            if action_result.action_type == "alert":
                alert_events.append((event_index, event))
                result.event_actions[event_index] = action_result
                event_trace.outcome = "alert"
            elif action_result.action_type == "filter":
                event_trace.outcome = "filter"
            elif action_result.action_type == "stop":
                event_trace.outcome = "stop"
                trace.event_traces.append(event_trace)
                break
            elif action_result.action_type == "discard":
                event_trace.outcome = "discard"
                trace.event_traces.append(event_trace)
                trace.stream_events.append(StreamEvent(
                    event_type="discard",
                    at_event_index=event_index,
                ))
                result.discarded = True
                result.trace = trace
                result.captured_queries = self.query_recorder.export()
                return result
            elif action_result.action_type == "log":
                alert_events.append((event_index, event))
                result.event_actions[event_index] = ActionResult(action_type="alert")
                event_trace.outcome = "alert"
            elif action_result.action_type == "timeout":
                elapsed = datetime.datetime.now(datetime.timezone.utc) - start_time
                logging.warning(
                    "correlation timeout reached after %s for %s while processing event %s, "
                    "remaining steps skipped and event falls through to alert",
                    elapsed, self._hunt_label(), event_index,
                )
                trace.stream_events.append(StreamEvent(
                    event_type="timeout",
                    at_event_index=event_index,
                    detail=f"timeout after {elapsed} mid-event; remaining steps skipped",
                ))
                alert_events.append((event_index, event))
                result.event_actions[event_index] = ActionResult(action_type="alert")
                event_trace.outcome = "timeout"

            trace.event_traces.append(event_trace)
            event_index += 1

        result.events = [event for _, event in alert_events]
        result.alert_event_origin_indices = [idx for idx, _ in alert_events]
        result.trace = trace
        result.captured_queries = self.query_recorder.export()
        return result

    def _hunt_label(self) -> str:
        """Human/greppable hunt identity for diagnostic logs (timeouts, etc.)."""
        if self.hunt_name and self.hunt_uuid:
            return f"hunt {self.hunt_name} (uuid={self.hunt_uuid})"
        if self.hunt_name:
            return f"hunt {self.hunt_name}"
        if self.hunt_uuid:
            return f"hunt uuid={self.hunt_uuid}"
        return "correlate hunt"

    @staticmethod
    def _append_step_trace_on_error(se: "_StepError", trace_steps: Optional[list[StepTrace]]) -> None:
        """Append a failing step's trace to the parent trace list exactly once.

        A _StepError may propagate through several levels of _process_event_steps
        (e.g. when a transform inside a condition's branch fails). The innermost
        catcher appends the step trace and clears se.step_trace so outer catchers
        don't add duplicates. Outer levels may reassign se.step_trace to a wrapping
        step (e.g. the enclosing condition) before re-raising.
        """
        if trace_steps is not None and se.step_trace is not None:
            trace_steps.append(se.step_trace)
        se.step_trace = None

    def _process_event_steps(
        self,
        steps: list[StepConfig],
        event: dict,
        events: list[dict],
        event_index: int,
        start_time: datetime.datetime,
        start_step_index: int = 0,
        trace_steps: Optional[list[StepTrace]] = None,
    ) -> Optional[ActionResult]:
        """Process an event through a list of steps.

        Returns an ActionResult if an interrupt occurred, None otherwise.
        Raises _StreamReset if a stream transform replaces the event stream.
        Raises _StepError if any step fails; the affected event short-circuits
        to alert at the top-level execute() loop.
        """
        for step_idx in range(start_step_index, len(steps)):
            step = steps[step_idx]

            elapsed = datetime.datetime.now(datetime.timezone.utc) - start_time
            if elapsed >= self.timeout:
                return ActionResult(action_type="timeout")

            if step.debug:
                self._render_debug(step.debug, event, events)

            # wall time for this step. For condition steps this is inclusive of the
            # nested branch steps run by _execute_condition (each of which is timed the
            # same way by the recursive _process_event_steps call).
            step_t0 = time.perf_counter()

            if isinstance(step.step, ConditionConfig):
                try:
                    action_result, step_trace = self._execute_condition(
                        step.step, event, events, event_index, start_time, step.description,
                    )
                except _StepError as se:
                    if se.step_trace is not None:
                        se.step_trace.duration_ms = (time.perf_counter() - step_t0) * 1000.0
                    self._append_step_trace_on_error(se, trace_steps)
                    raise
                step_trace.duration_ms = (time.perf_counter() - step_t0) * 1000.0
                if trace_steps is not None:
                    trace_steps.append(step_trace)
                if action_result is not None and action_result.is_interrupt:
                    return action_result

            elif isinstance(step.step, TransformConfig):
                try:
                    action_result, step_trace = self._execute_transform(
                        step.step, event, events, event_index, step_idx, step.description,
                        trace_steps,
                    )
                except _StepError as se:
                    if se.step_trace is not None:
                        se.step_trace.duration_ms = (time.perf_counter() - step_t0) * 1000.0
                    self._append_step_trace_on_error(se, trace_steps)
                    raise
                # step_trace is None on the _StreamReset path (its duration is set inside
                # _execute_transform before the reset propagates).
                if step_trace is not None:
                    step_trace.duration_ms = (time.perf_counter() - step_t0) * 1000.0
                    if trace_steps is not None:
                        trace_steps.append(step_trace)
                if action_result is not None and action_result.is_interrupt:
                    return action_result
                # Note: if _StreamReset is raised, it propagates up

            elif isinstance(step.step, ActionConfig):
                try:
                    action_result = execute_action(step.step, event, events, self._secrets, self._config)
                except Exception as e:
                    logging.error("error executing action: %s", e, exc_info=True)
                    action_trace = ActionTrace(
                        action_type=step.step.type,
                        is_interrupt=False,
                        error=str(e),
                    )
                    step_trace = StepTrace(description=step.description, step=action_trace)
                    step_trace.duration_ms = (time.perf_counter() - step_t0) * 1000.0
                    if trace_steps is not None:
                        trace_steps.append(step_trace)
                    raise _StepError(str(e), None) from e
                if trace_steps is not None:
                    step_trace = self._trace_action(step.step, action_result, event, events, step.description)
                    step_trace.duration_ms = (time.perf_counter() - step_t0) * 1000.0
                    trace_steps.append(step_trace)
                if action_result.is_interrupt:
                    return action_result

        return None

    def _execute_condition(
        self,
        condition: ConditionConfig,
        event: dict,
        events: list[dict],
        event_index: int,
        start_time: datetime.datetime,
        description: Optional[str] = None,
    ) -> tuple[Optional[ActionResult], StepTrace]:
        """Execute a condition step. Returns (action_result, step_trace).

        Raises _StepError if expression evaluation fails.
        """
        expr_result, expr_trace = evaluate_expression_traced(
            condition.when, event, events, self._secrets, self._config,
        )
        # Sanitize any rendered values that may contain secrets
        if expr_trace.rendered_value is not None:
            expr_trace.rendered_value = sanitize_value(expr_trace.rendered_value, self._secrets)

        condition_trace = ConditionTrace(expression=expr_trace, branch_taken="none")
        step_trace = StepTrace(description=description, step=condition_trace)

        if expr_trace.error is not None:
            logging.error("error evaluating condition expression: %s", expr_trace.error)
            condition_trace.error = expr_trace.error
            raise _StepError(expr_trace.error, step_trace)

        if expr_result:
            condition_trace.branch_taken = "execute"
            try:
                action_result = self._process_event_steps(
                    condition.execute, event, events, event_index, start_time,
                    trace_steps=condition_trace.branch_steps,
                )
            except _StepError as se:
                # Inner step failed and its trace was already attached to branch_steps.
                # Reassign the step_trace carrier to our condition so the outer caller
                # appends the condition (with the nested failure visible) to its trace.
                se.step_trace = step_trace
                raise
            return action_result, step_trace
        elif condition.else_:
            condition_trace.branch_taken = "else"
            try:
                action_result = self._process_event_steps(
                    condition.else_, event, events, event_index, start_time,
                    trace_steps=condition_trace.branch_steps,
                )
            except _StepError as se:
                se.step_trace = step_trace
                raise
            return action_result, step_trace

        return None, step_trace

    def _execute_transform(
        self,
        transform: TransformConfig,
        event: dict,
        events: list[dict],
        event_index: int,
        current_step_index: int,
        description: Optional[str] = None,
        parent_trace_steps: Optional[list[StepTrace]] = None,
    ) -> tuple[Optional[ActionResult], Optional[StepTrace]]:
        """Execute a transform step.

        Returns (action_result, step_trace). action_result is always None on
        the normal return path — transforms do not produce interrupts.
        step_trace is None when _StreamReset is raised (it was already appended to parent_trace_steps).
        Raises _StreamReset if a stream transform succeeded.
        Raises _StepError if the command fails.
        """
        transform_trace = TransformTrace(
            transform_type=transform.type,
            method=transform.method,
            command_type=transform.command.type,
        )
        step_trace = StepTrace(description=description, step=transform_trace)

        # Stream transforms append their own step_trace and raise _StreamReset before
        # returning to the caller's loop, so the loop never times them. Measure here and
        # stamp the duration onto step_trace just before the reset propagates.
        transform_t0 = time.perf_counter()

        # Build a summary of the rendered command for the trace
        transform_trace.rendered_command = sanitize_value(
            self._render_command_summary(transform.command, event, events),
            self._secrets,
        )

        # Capture the resolved query window for tracing. _resolve_time_range will
        # run again inside execute_command; calling it here is cheap and lets us
        # record the bounds even if a later failure prevents execute_command from
        # completing. Failures here are non-fatal — the real execution path will
        # surface them as _StepError.
        effective_query_command = self._effective_query_command(transform.command)
        if effective_query_command is not None:
            try:
                q_start, q_end = _resolve_time_range(
                    effective_query_command, event, transform.type,
                    self.hunt_start_time, self.hunt_end_time, self._current_source,
                )
                transform_trace.query_start_time = q_start
                transform_trace.query_end_time = q_end
                try:
                    source = get_query_source(effective_query_command.source)
                except ValueError:
                    source = None
                if source is not None:
                    transform_trace.query_time_spec = source.format_timespec_for_display(q_start, q_end)
            except Exception:
                pass

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                output = execute_command(
                    transform.command,
                    event,
                    events,
                    transform.type,
                    self.predefined_commands,
                    self.hunt_start_time,
                    temp_dir,
                    self.stream_query_cache,
                    self._secrets,
                    self._config,
                    self._current_source,
                    hunt_end_time=self.hunt_end_time,
                    query_recorder=self.query_recorder,
                )

            # Count result rows from command output
            output_lines = [line for line in output.strip().splitlines() if line.strip()] if output else []
            transform_trace.result_count = len(output_lines)

            updated_event, new_stream, merge_dropped = apply_transform(transform, output, event, events)
            if merge_dropped is not None:
                transform_trace.merge_dropped = merge_dropped

            if new_stream is not None:
                # a stream mutate driven by a query replaces the stream's origin;
                # update the tracked source so subsequent default lookups use the new system.
                # mutate by executable / merge by query / merge by executable leave the source unchanged.
                if transform.method == "mutate":
                    new_source = self._resolve_command_source(transform.command)
                    if new_source is not None:
                        self._current_source = new_source

                # Append trace before raising since the exception skips the caller's append
                step_trace.duration_ms = (time.perf_counter() - transform_t0) * 1000.0
                if parent_trace_steps is not None:
                    parent_trace_steps.append(step_trace)
                # Stream transform - signal reset, resume at next step
                raise _StreamReset(new_stream, current_step_index + 1)
            elif updated_event is not None:
                events[event_index] = updated_event
                # Record property details for event/property transforms
                if transform.method == "property" and transform.property_name:
                    transform_trace.property_name = transform.property_name
                    prop_val = updated_event.get(transform.property_name)
                    transform_trace.property_value = _truncate_repr(prop_val)

            return None, step_trace

        except _StreamReset:
            raise  # Re-raise stream reset signals (step_trace already appended above)
        except Exception as e:
            logging.error("error executing transform command: %s", e, exc_info=True)
            transform_trace.error = str(e)
            raise _StepError(str(e), step_trace) from e

    def _trace_action(
        self,
        action: ActionConfig,
        action_result: ActionResult,
        event: dict,
        events: list[dict],
        description: Optional[str] = None,
    ) -> StepTrace:
        """Build a StepTrace for an action execution."""
        rendered_log_message = None
        if action.log_message:
            try:
                context = build_jinja_context(event, events, self._secrets, self._config)
                rendered_log_message = sanitize_value(
                    _jinja_env.from_string(action.log_message).render(**context),
                    self._secrets,
                )
            except Exception:
                pass
        return StepTrace(
            description=description,
            step=ActionTrace(
                action_type=action_result.action_type,
                rendered_log_message=rendered_log_message,
                is_interrupt=action_result.is_interrupt,
            ),
        )

    def _resolve_command_source(self, command: CommandConfig) -> Optional[str]:
        """Return the query source name a command resolves to, or None if not a query."""
        if command.type == "query":
            return command.source
        if command.type == "defined" and command.name:
            for predef in self.predefined_commands:
                if predef.name == command.name and predef.type == "query":
                    return predef.source
        return None

    def _effective_query_command(self, command: CommandConfig) -> Optional[CommandConfig]:
        """Return the CommandConfig that will actually execute against a QuerySource,
        resolving `defined` indirection. Returns None for non-query commands."""
        if command.type == "query":
            return command
        if command.type == "defined" and command.name:
            for predef in self.predefined_commands:
                if predef.name == command.name and predef.type == "query":
                    return predef.to_command_config(command.arguments)
        return None

    def _render_command_summary(
        self,
        command: CommandConfig,
        event: dict,
        events: list[dict],
    ) -> Optional[str]:
        """Render a human-readable summary of the command for tracing."""
        context = build_jinja_context(event, events, self._secrets, self._config)
        try:
            if command.type == "query" and command.query:
                return _jinja_env.from_string(command.query).render(**context)
            elif command.type == "executable" and command.path:
                rendered_args = []
                if command.args:
                    for arg in command.args:
                        rendered_args.append(_jinja_env.from_string(arg).render(**context))
                return f"{command.path} {' '.join(rendered_args)}".strip()
            elif command.type == "defined" and command.name:
                return f"defined:{command.name}"
        except Exception:
            pass
        return None

    def _render_debug(self, template: str, event: dict, events: list[dict]):
        """Render and log a debug message."""
        try:
            context = build_jinja_context(event, events, self._secrets, self._config)
            message = _jinja_env.from_string(template).render(**context)
            logging.debug("correlation debug: %s", message)
        except Exception:
            logging.debug("failed to render debug template: %s", template, exc_info=True)
