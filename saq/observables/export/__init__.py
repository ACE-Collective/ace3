"""Export of the observables that are enabled for detection to the systems that run detection rules.

An export target is pluggable the same way an analysis module is: a top-level
``observable_export_<name>:`` config block names a python module and class, which is imported and
instantiated at run time. Integrations can therefore add their own export targets purely through
configuration.

A target that filters by observable type does so through
:func:`saq.observables.export.base.select_detections`, which is subtype-aware: an ``export_list``
entry covers its own type and every type that extends it (docs/OBSERVABLE_TYPE_INHERITANCE.md), and
the covered detections are exported under the configured type.

See :mod:`saq.observables.export.base` for the interface an export target implements and
:mod:`saq.observables.export.manager` for the two-stage run.
"""
