# The package init runs in every ACE process (initialize_integrations() imports it), so it imports only
# what the hooks every process needs register, and this integration has none of those. The analyzer lives
# in example/modules.py, which the engine imports from its analysis_module_example block. The API router
# (example/api/router.py) and the GUI blueprint (example/app/blueprint.py), which also registers the
# observable action, are named in the integration_example: block of etc/saq.integration.yaml, and only the
# API and the GUI import them (docs/IMPORTS.md).
