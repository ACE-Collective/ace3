"""Export of the observables that are enabled for detection to the systems that run detection rules.

An export target is pluggable the same way an analysis module is: a top-level
``observable_export_<name>:`` config block names a python module and class, which is imported and
instantiated at run time. Integrations can therefore add their own export targets purely through
configuration.

See :mod:`saq.observables.export.base` for the interface an export target implements and
:mod:`saq.observables.export.manager` for the two-stage run.
"""
