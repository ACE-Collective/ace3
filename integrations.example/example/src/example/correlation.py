"""An example custom correlation command type.

Registered as `example_echo` by the `hunter.correlation.command_types` entry in
etc/saq.integration.yaml. A hunt uses it like this:

    - transform:
        type: event
        method: property
        property_name: echoed
        property_type: list
        command:
          type: example_echo
          options:
            message: "hello {{ _event.user }}"
            repeat: 2

See "Extending correlation hunts" in docs/INTEGRATIONS.md.
"""

import json

from pydantic import BaseModel, Field

from saq.collectors.hunter.correlation.command_types import CommandContext, CorrelationCommand


class EchoOptions(BaseModel):
    # forbid extra keys so a typo in a hunt's options is reported by hunt validation
    model_config = {"extra": "forbid"}

    message: str = Field(..., description="the message to echo (already jinja-rendered by core)")
    repeat: int = Field(default=1, ge=1, le=100, description="how many rows to return")


class ExampleEchoCommand(CorrelationCommand):
    """Returns `repeat` JSONL rows of `{"message": ...}`.

    A real command type would call out to some system here, honouring `context.timeout`, and would
    read any credentials it needs from its integration's configuration.
    """

    config_class = EchoOptions

    def execute(self, context: CommandContext, options: EchoOptions) -> str:
        return "\n".join(json.dumps({"message": options.message}) for _ in range(options.repeat))

    def cache_key(self, context: CommandContext, options: EchoOptions) -> dict:
        # the output depends only on the rendered options, never on the rest of the event, so the
        # cache can be shared by every event that renders the same message
        return {"options": options.model_dump()}
