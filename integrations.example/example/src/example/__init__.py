# The package init runs in every ACE process (initialize_integrations() imports it), so it imports only
# what the hooks every process needs register, and this integration has none of those. The analyzer lives
# in example/modules.py, which the engine imports from its analysis_module_example block; the observable
# action and the blueprint in example/gui.py, which only the GUI imports (gui_module); and the API routes
# in example/api/router.py, which only the API imports (api_module). See docs/IMPORTS.md.
