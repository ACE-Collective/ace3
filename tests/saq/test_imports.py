"""What importing ACE's entry points needs installed, and what it loads.

Each test imports in a fresh interpreter: the test process itself has imported nearly the whole
codebase before any test runs, so an import cycle or a heavy import is invisible from inside it.
"""

import importlib
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

import saq.database
from saq.configuration.config import get_config
from saq.environment import get_base_dir
from saq.integration.integration_util import get_valid_integration_dirs
from tests.saq.helpers import run_python

pytestmark = pytest.mark.unit


def _assert_loads_none(imports: str, forbidden: list[str], timeout: int = 120):
    """Runs imports in a fresh interpreter and fails if any of the forbidden modules is loaded after it."""
    run_python(f"import sys\n{imports}"
               f"loaded = [name for name in {forbidden!r} if name in sys.modules]\n"
               "assert not loaded, loaded\n", timeout=timeout)


_INITIALIZE_CONFIGURATION = ("from saq.environment import get_global_runtime_settings, initialize_base_dir\n"
                             "get_global_runtime_settings().unit_testing = True\n"
                             "initialize_base_dir()\n"
                             "from saq.configuration import initialize_configuration\n"
                             "from saq.integration.integration_loader import load_integrations\n"
                             "load_integrations()\n"
                             "initialize_configuration()\n")


def test_saq_imports_without_yara_scanner():
    # the drift check (.github/workflows/check-model-drift.yml) installs only
    # installer/requirements-pinned.txt, and its alembic env imports saq; yara_scanner_v2 comes from
    # git in the image, so nothing on that path may import it. The API is held to the same rule.
    run_python("import sys\n"
               "sys.modules['yara_scanner'] = None\n"
               "import saq, aceapi_v2.application\n"
               "from saq.database.meta import Base\n")


def test_saq_does_not_import_the_api():
    # aceapi_v2 imports the analysis tree and saq.svs at module level, so saq importing aceapi_v2
    # back makes a cycle that breaks whichever side is imported first
    run_python("import sys\n"
               "import saq, saq.logging, saq.svs.association, saq.svs.attribution, saq.svs.hosts, saq.svs.maintenance\n"
               "api = sorted(name for name in sys.modules if name.split('.')[0] == 'aceapi_v2')\n"
               "assert not api, api\n")


def test_importing_saq_imports_nothing_else():
    # saq.lazy_exports is the helper the init builds its __getattr__ with, and imports only importlib
    run_python("import sys\n"
               "import saq\n"
               "loaded = sorted(name for name in sys.modules if name.startswith('saq.') and name != 'saq.lazy_exports')\n"
               "assert not loaded, loaded\n")


def test_saq_exports_load_on_first_use():
    # integrations import these from saq (integrations.example does)
    run_python("import sys\n"
               "from saq import Analysis, AnalysisModule, Observable, RootAnalysis\n"
               "from saq.analysis.analysis import Analysis as A\n"
               "from saq.analysis.observable import Observable as O\n"
               "from saq.analysis.root import RootAnalysis as R\n"
               "from saq.modules.base_module import AnalysisModule as M\n"
               "assert (Analysis, Observable, RootAnalysis, AnalysisModule) == (A, O, R, M)\n"
               "try:\n"
               "    from saq import NoSuchName\n"
               "except ImportError:\n"
               "    pass\n"
               "else:\n"
               "    raise AssertionError('saq exported a name it does not define')\n")


def test_configuration_does_not_import_the_analysis_framework():
    # every process reads its configuration, so every process pays for what config parsing imports. It
    # validates each analysis module and observable export block against a pydantic base class, and
    # those must not drag in the analysis framework, the observable types or the database models.
    _assert_loads_none(_INITIALIZE_CONFIGURATION,
                       ["saq.modules.base_module", "saq.observables.base", "saq.observables.generator",
                        "saq.database.model", "sqlalchemy", "flask"])


def test_the_example_integration_registers_without_loading_what_it_registers():
    # integration authors start from integrations.example, and initialize_integrations() imports its package
    # in every process: its analyzer, blueprint and API router load only where they are used. Nothing in
    # the package names the router or the blueprint: its integration_example: block does
    src = os.path.join(get_base_dir(), "integrations.example", "example", "src")
    _assert_loads_none(f"sys.path.insert(0, {src!r})\n"
                       "import example\n",
                       ["example.modules", "example.app", "example.api", "saq.observables.base",
                        "saq.modules.base_module", "saq.analysis.root", "aceapi_v2", "app", "flask", "werkzeug",
                        "fastapi"])


def test_the_example_integration_declares_its_router_and_blueprint():
    # the API and the GUI import what its integration_example: block names
    integration_dir = os.path.join(get_base_dir(), "integrations.example", "example")
    run_python("import importlib, sys, yaml\n"
               f"sys.path.insert(0, {os.path.join(integration_dir, 'src')!r})\n"
               "from fastapi import APIRouter\n"
               "from flask import Flask\n"
               "from saq.configuration.schema import IntegrationConfig\n"
               f"with open({os.path.join(integration_dir, 'etc', 'saq.integration.yaml')!r}) as fp:\n"
               "    config = IntegrationConfig.model_validate(yaml.safe_load(fp)['integration_example'])\n"
               "def load(target):\n"
               "    module_name, attribute = target.split(':')\n"
               "    return getattr(importlib.import_module(module_name), attribute)\n"
               "assert isinstance(load(config.api_router), APIRouter)\n"
               "flask_app = Flask('test')\n"
               "load(config.gui_blueprint)(flask_app)\n"
               "assert 'example.index' in flask_app.view_functions, flask_app.view_functions\n")


def test_sql_timing_listeners_come_with_the_first_engine():
    # every process that builds an engine gets them, not only the ones that also load the GUI; importing the
    # pool alone builds none, so it must not import SQLAlchemy either
    run_python("import sys\n"
               "from saq.database import pool\n"
               "assert 'sqlalchemy' not in sys.modules\n"
               "from sqlalchemy import Engine, create_engine, event\n"
               "assert not event.contains(Engine, 'before_cursor_execute', pool._before_cursor_execute)\n"
               "pool._attach_engine_listeners(create_engine('sqlite://'))\n"
               "assert event.contains(Engine, 'before_cursor_execute', pool._before_cursor_execute)\n"
               "assert event.contains(Engine, 'after_cursor_execute', pool._after_cursor_execute)\n"
               "assert 'app' not in sys.modules\n")


def test_building_an_observable_imports_only_its_type():
    # an observable type's module is imported the first time an observable of that type is built: the
    # package, the generator, the hierarchy and the export config import none of them
    run_python(f"import sys\n{_INITIALIZE_CONFIGURATION}"
               "import saq.observables, saq.observables.type_hierarchy, saq.observables.export.config\n"
               "from saq.observables import create_observable\n"
               "from saq.configuration import get_config\n"
               "type_modules = {target.split(':')[0] for target in get_config().observable_types.classes.values()}\n"
               "loaded = sorted(type_modules & set(sys.modules))\n"
               "assert not loaded, loaded\n"
               "assert 'saq.gui' not in sys.modules\n"
               "assert type(create_observable('url', 'https://example.com/')).__name__ == 'URLObservable'\n"
               "loaded = sorted(type_modules & set(sys.modules))\n"
               "assert loaded == ['saq.observables.network.http'], loaded\n")


@pytest.mark.integration
def test_initialization_does_not_import_what_only_some_processes_need(tmp_path):
    # a process that never looks at an observable or queries through the ORM (network semaphore, git,
    # monitoring, cron) must not pay for the observable types, the analysis framework, the engine, the
    # models, the analysis tree or the GUI just by initializing. Initializing sets up the database
    # connections (pool, retry, node registration), so this holds those modules to the same rule. This
    # runs with the integrations installed here, so it also catches one of them importing any of these
    # at module level.
    data_dir, temp_dir = tmp_path / "data", tmp_path / "temp"
    data_dir.mkdir()
    temp_dir.mkdir()
    _assert_loads_none("from saq.environment import get_global_runtime_settings, initialize_environment\n"
                       "get_global_runtime_settings().unit_testing = True\n"
                       f"initialize_environment(saq_home={get_base_dir()!r}, data_dir={str(data_dir)!r}, "
                       f"temp_dir={str(temp_dir)!r}, config_paths=[])\n",
                       ["saq.observables.base", "saq.observables.generator", "saq.modules.base_module",
                        "saq.engine.core", "saq.database.model",
                        "saq.analysis.root", "saq.gui.alert", "flask", "werkzeug", "urlfinderlib", "requests",
                        "celery", "phishkit", "botocore", "boto3", "sqlalchemy"],
                       timeout=180)


def test_the_models_and_url_helpers_do_not_import_flask_urlfinderlib_or_requests():
    # saq.util imports the url helpers in every process, and the models use them; only extracting a protected
    # url needs urlfinderlib or requests, and only the GUI needs Flask
    _assert_loads_none("import saq.util.url, saq.database.model\n",
                       ["flask", "flask_login", "werkzeug", "urlfinderlib", "requests"])


def test_saq_database_exports_load_on_first_use():
    for name, target in saq.database._EXPORTS.items():
        module_name, attribute = target if isinstance(target, tuple) else (target, name)
        assert getattr(saq.database, name) is getattr(importlib.import_module(module_name), attribute), name

    with pytest.raises(AttributeError):
        saq.database.NoSuchName  # noqa: B018


def test_registering_observable_actions_does_not_import_the_models_or_the_gui():
    # the observable types and the integrations register their presenters, actions and remediation
    # interfaces through these in every process
    _assert_loads_none("import saq.analysis.presenter.observable_presenter, saq.gui.observable_actions.base, "
                       "saq.gui.alert_actions, saq.remediation.target\n",
                       ["saq.database.model", "saq.analysis.root", "saq.gui.alert", "flask"])


@pytest.mark.parametrize("app_module", ["app.application", "aceapi_v2.application"])
def test_the_apps_register_the_root_analysis_presenter(app_module):
    # saq.gui.alert registers it when imported; saq.gui no longer imports it for everyone, so the
    # processes that render an alert have to import it themselves
    run_python("import importlib\n"
               f"importlib.import_module({app_module!r})\n"
               "from saq.analysis.presenter.analysis_presenter import create_analysis_presenter\n"
               "from saq.analysis.root import RootAnalysis\n"
               "from saq.gui.alert import GUIAlertPresenter\n"
               "assert isinstance(create_analysis_presenter(RootAnalysis()), GUIAlertPresenter)\n", timeout=180)


@pytest.mark.parametrize("package", ["saq.analysis", "saq.gui", "saq.collectors.hunter", "saq.modules.file_analysis",
                                     "saq.observables"])
def test_package_exports_load_on_first_use(package):
    module = importlib.import_module(package)
    for name, module_name in module._EXPORTS.items():
        assert getattr(module, name) is getattr(importlib.import_module(module_name), name), name

    with pytest.raises(AttributeError):
        getattr(module, "NoSuchName")


def test_one_file_analysis_module_imports_only_itself():
    # the svs capture and the search extractors import a few of them to read their analysis; the others bring
    # in the OCR, office and PDF libraries
    _assert_loads_none("import saq.modules.file_analysis.yara, saq.modules.file_analysis.xml\n",
                       ["saq.modules.file_analysis.ocr", "saq.modules.file_analysis.olevba",
                        "saq.modules.file_analysis.pdf", "pytesseract", "oletools"])


def test_ocr_does_not_import_pandas():
    # pytesseract imports pandas whenever it is installed, which costs every engine worker and GUI process 27 MB;
    # ACE uses only image_to_string(), so pandas isn't in installer/requirements.txt
    run_python("import sys\n"
               "import saq.ocr, saq.modules.file_analysis.ocr\n"
               "assert 'pytesseract' in sys.modules\n"
               "assert 'pandas' not in sys.modules, 'pandas is installed, and pytesseract imported it'\n")


def test_reading_analysis_does_not_import_the_analysis_tools():
    # the search indexer reads these modules' analysis, and loading any alert imports each analysis class's module;
    # the libraries the analyzers run (OCR, oletools, the RDAP and WHOIS clients, pikepdf, celery) load when they run
    _assert_loads_none("import saq.search.extractors\n",
                       ["cv2", "pytesseract", "saq.ocr", "oletools", "whoisit", "whois", "tldextract", "pikepdf",
                        "celery"])


def test_the_api_packages_import_nothing():
    # importing any module of a package runs its init
    run_python("import sys\n"
               "import aceapi_v2, aceapi_ai, app\n"
               "loaded = sorted(name for name in sys.modules if name.split('.')[0] in ('aceapi_v2', 'aceapi_ai', 'app') "
               "and '.' in name)\n"
               "assert not loaded, loaded\n")


def test_the_engine_api_does_not_import_the_user_api():
    # the http-api-engine container serves only the engine, health and common routes
    _assert_loads_none("import aceapi_v2.app_factory\n",
                       ["aceapi_v2.application", "aceapi_v2.alerts", "aceapi_v2.svs", "aceapi_ai"])


def test_serving_an_api_imports_no_routes():
    # the AI API's entry point imports it too, and serves none of API v2's routers
    _assert_loads_none("import aceapi_v2.serving\n", ["aceapi_v2.app_factory", "aceapi_v2.application",
                                                       "aceapi_v2.engine", "saq.engine"])


def test_importing_the_api_application_builds_no_app():
    # the API entry points import it to call create_app() themselves, and the tests get theirs from
    # tests/aceapi_v2/conftest.py::v2_app()
    run_python("from fastapi import FastAPI\n"
               "built = []\n"
               "init = FastAPI.__init__\n"
               "FastAPI.__init__ = lambda self, *args, **kwargs: (built.append(self), init(self, *args, **kwargs))[1]\n"
               "import aceapi_v2.application as application\n"
               "assert not built and not hasattr(application, 'app'), built\n")


def test_importing_ace_api_does_not_import_requests():
    # initialize_environment() imports it in every process to set its defaults
    _assert_loads_none("import ace_api\n", ["requests", "pprint"])


def test_ace_api_still_says_how_to_install_a_missing_requests():
    code = ("import sys\n"
            "sys.modules['requests'] = None\n"
            "import ace_api\n")
    result = subprocess.run([sys.executable, "-c", code], cwd=get_base_dir(), capture_output=True, text=True,
                            timeout=120)
    assert result.returncode == 1
    assert "pip install requests" in result.stderr


def test_the_email_archive_and_phishkit_clients_load_their_libraries_on_use():
    # initialize_environment() sets up the email archive in every process, and the S3 backend is imported
    # with it even where it is configured; only archiving through S3 or scanning needs boto or celery
    _assert_loads_none("import saq.email_archive, saq.email_archive.s3, saq.storage, saq.phishkit\n",
                       ["boto3", "botocore", "saq.storage.s3", "celery", "phishkit"])


# modules whose import closures loop back through saq.analysis.presenter, imported first so a re-export
# there cannot close a cycle again (see the comment in saq/analysis/presenter/__init__.py)
CYCLE_MODULES = ["saq.database.model", "saq.gui", "saq.analysis.presenter.observable_presenter",
                 "saq.observables.generator"]

# what the ace script, the API containers and the GUI import first
CLI_AND_APPS = ["saq.cli.cli_main", "saq.cli.commands", "aceapi_v2.application", "aceapi_v2.app_factory",
                "aceapi_ai.application",
                "app.application"]


def _integration_paths() -> str:
    """Code that puts the integrations' source directories on sys.path, the way load_integrations() does
    before anything imports an integration's service."""
    src_paths = [os.path.join(path, "src") for path in get_valid_integration_dirs()
                 if os.path.isdir(os.path.join(path, "src"))]
    return f"import sys\nsys.path.extend({src_paths!r})\n"


def _import_first(entry_point: str, setup: str) -> subprocess.CompletedProcess:
    # a service is module:Class, and load_service() imports the module and then gets the class, which is what
    # imports the service when the module is a lazy package
    module, _, name = entry_point.partition(":")
    code = f"{setup}import importlib\nmodule = importlib.import_module({module!r})\n"
    if name:
        code += f"getattr(module, {name!r})\n"
    return subprocess.run([sys.executable, "-c", code], cwd=get_base_dir(), capture_output=True, text=True,
                          timeout=300)


def _import_failures(modules: list[str], setup: str) -> str:
    # one interpreter per module, a few at a time: each import takes a second or two
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = dict(zip(modules, pool.map(lambda module: _import_first(module, setup), modules)))

    return "\n\n".join(f"{module}:\n" + "\n".join(result.stderr.strip().splitlines()[-8:])
                       for module, result in results.items() if result.returncode != 0)


def _entry_points() -> list[str]:
    services = sorted({f"{service.python_module}:{service.python_class}" for service in get_config().services})
    # create_observable() imports these one at a time, so any of them can be the first a process imports
    observable_types = sorted({target.split(":")[0] for target in get_config().observable_types.classes.values()})
    return CYCLE_MODULES + observable_types + services + CLI_AND_APPS


def test_entry_points_import_first():
    failures = _import_failures(_entry_points(), _integration_paths())
    assert not failures, failures


# services that need neither the API, the GUI, the search client, the observables nor the analysis tools, and
# packages that belong to those. Each of these services is a process of its own on every node, so an import that
# pulls one of these packages in costs every one of them that package's memory.
LIGHT_SERVICES = ["saq.network_semaphore.service", "saq.git", "saq.monitoring.service", "saq.cron",
                  "saq.remediation.service", "saq.remediation.external.service", "saq.yara_scanning.service",
                  "saq.svs.service"]
HEAVY_PACKAGES = ["aceapi_v2", "aceapi_ai", "app", "fastapi", "flask", "werkzeug", "qdrant_client", "numpy", "grpc",
                  "celery", "botocore", "pandas", "cv2", "torch", "saq.observables.base", "saq.observables.generator",
                  "urlfinderlib", "requests"]

# these need no database either, so neither the models nor the analysis framework
NO_DATABASE_SERVICES = ["saq.network_semaphore.service", "saq.git", "saq.monitoring.service", "saq.cron"]
DATABASE_MODULES = ["sqlalchemy", "saq.database.model", "saq.modules.base_module"]


@pytest.mark.parametrize("module", LIGHT_SERVICES)
def test_light_service_does_not_import_heavy_packages(module):
    forbidden = HEAVY_PACKAGES + (DATABASE_MODULES if module in NO_DATABASE_SERVICES else [])
    _assert_loads_none(f"import importlib\nimportlib.import_module({module!r})\n", forbidden, timeout=300)


def test_the_hunter_does_not_import_the_gui():
    # the hunter builds observables and renders summaries with jinja2, but serves no page; it reaches the
    # observable types, which used to load urlfinderlib for one method
    _assert_loads_none("import importlib\nimportlib.import_module('saq.collectors.hunter').HunterService\n",
                       ["flask", "werkzeug", "saq.gui.alert", "app", "aceapi_v2", "urlfinderlib"], timeout=300)
