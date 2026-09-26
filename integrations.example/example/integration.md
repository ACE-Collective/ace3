# Example Integration

A starting point for a new integration. See `docs/INTEGRATIONS.md` for the layout and the
extension points it demonstrates.

## Correlation command type: `example_echo`

`src/example/correlation.py` registers a custom correlation command type (through
`hunter.correlation.command_types` in `etc/saq.integration.yaml`). It returns `repeat` JSONL rows of
`{"message": ...}`, which makes it a minimal, network-free template for a real one.

```yaml
rule:
  correlate:
    logic:
      - transform:
          type: event
          method: property
          property_name: echoed
          property_type: list
          command:
            type: example_echo
            cache: 1h
            options:
              message: "hello {{ _event.user }}"
              repeat: 2
      - when: "{{ _event.echoed | length == 2 }}"
        execute:
          - action: alert
```
