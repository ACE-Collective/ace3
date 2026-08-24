import argparse
import fnmatch
import logging
import os
import sys
from typing import Optional

import yaml

from saq.cli.cli_main import get_cli_subparsers
from saq.configuration import get_config
from saq.environment import get_global_runtime_settings


def list_available_modules(args):
    from saq.engine.engine_configuration import EngineConfiguration
    from saq.engine.configuration_manager import ConfigurationManager
    from saq.engine.enums import EngineType
    configuration_manager = ConfigurationManager(EngineConfiguration(engine_type=EngineType.LOCAL, single_threaded_mode=True))
    configuration_manager.load_modules()

    for module in sorted(configuration_manager.analysis_modules, key=lambda x: x.module_id):
        print(f"{module.module_id}")

    sys.exit(0)

list_available_modules_parser = get_cli_subparsers().add_parser('list-available-modules',
    help="Lists the modules available in ACE.")
list_available_modules_parser.set_defaults(func=list_available_modules)

def config(args):
    if args.global_environment:
        if not args.settings:
            print(get_global_runtime_settings())
        
        for setting in args.settings:
            if args.value:
                print(str(getattr(get_global_runtime_settings(), setting)))
            else:
                print(f"{setting} = {getattr(get_global_runtime_settings(), setting)}")

        return 0

    def matches_param(section_name: str, key_name: Optional[str]=None) -> bool:
        if not args.settings:
            return True

        for spec in args.settings:
            if "." in spec:
                section_spec, key_spec = spec.split('.')
            else:
                section_spec = spec
                key_spec = None

            if key_spec:
                if fnmatch.fnmatch(section_name, section_spec) and ( key_name is None or fnmatch.fnmatch(key_name, key_spec) ):
                    return True
            else:
                if fnmatch.fnmatch(section_name, section_spec):
                    return True

        return False

    result = {}
    for section in list(get_config().raw._data.keys()):
        if not matches_param(section):
            continue

        result[section] = {}

        value = get_config().raw._data[section]

        if isinstance(value, dict):
            for key in list(get_config().raw._data[section].keys()):
                if matches_param(section, key):
                    result[section][key] = get_config().raw._data[section][key]
        else:
            result[section] = value

    # are we only printing the value out?
    if args.value:
        for section_key, section_dict in result.items():
            for key, value in section_dict.items():
                print(value)
    else:
        # otherwise we just dump what is queried for as yaml
        print(yaml.dump(result, indent=2))

    return 0

config_parser = get_cli_subparsers().add_parser('config',
    help="Queries the ACE configuration.")
config_parser.add_argument("-v", "--value", action="store_true", default=False, help="Only print the value on output.")
config_parser.add_argument("-g", "--global-environment", action="store_true", default=False, help="Pull the value from the global environment instead.")
config_parser.add_argument('settings', nargs="*",
    help="Zero or more configuration items to display in the format section.key.")
config_parser.set_defaults(func=config)

def display_workload(args):
    from saq.database import get_db_connection

    with get_db_connection() as db:
        c = db.cursor()
        c.execute("SELECT analysis_mode, COUNT(*) FROM workload WHERE company_id = %s GROUP BY analysis_mode ORDER BY analysis_mode", (get_config().global_settings.company_id,))
        print(f" -- WORKLOAD ({get_config().global_settings.company_name}) --")
        print("{: <15}{}".format('MODE', 'COUNT'))
        for analysis_mode, count in c:
            print("{: <15}{}".format(analysis_mode, count))

        db.commit()
        print()
        print(f" -- DELAYED WORKLOAD ({get_global_runtime_settings().saq_node})--")
        c.execute("SELECT storage_dir, analysis_module, COUNT(*) FROM delayed_analysis JOIN nodes ON delayed_analysis.node_id = nodes.id WHERE nodes.name = %s GROUP BY storage_dir, analysis_module", (get_global_runtime_settings().saq_node,))
        print("{: <36} {: <20} {}".format('UUID', 'MODULE', 'COUNT'))
        for storage_dir, analysis_module, count in c:
            storage_dir = os.path.basename(storage_dir)
            analysis_module = analysis_module[len('analysis_module_'):]
            print("{: <36} {: <20} {}".format(storage_dir, analysis_module, count))

        db.commit()
        print()
        print(f" -- LOCKS ({get_global_runtime_settings().saq_node}) --")
        c.execute("SELECT uuid, lock_uuid, lock_time, lock_owner FROM locks WHERE lock_owner LIKE CONCAT(%s, '-%%') ORDER BY lock_time", (get_global_runtime_settings().saq_node,))
        print("{: <36} {: <36} {: <19} {}".format('UUID', 'LOCK', 'TIME', 'OWNER'))
        for _uuid, lock_uuid, lock_time, lock_owner in c:
            print("{: <36} {: <36} {: <19} {}".format(_uuid, lock_uuid, str(lock_time), lock_owner))
        db.commit()

    sys.exit(0)

display_workload_parser = get_cli_subparsers().add_parser('display-workload',
    help="Displays the current ACE workload.")
display_workload_parser.set_defaults(func=display_workload)

def generate_api_key(args):
    import uuid
    from saq.util import sha256_str
    api_key = str(uuid.uuid4())
    print(f"api_key = {api_key}")
    print(f"api_key_sha256 = {sha256_str(api_key)}")
    sys.exit(0)

generate_api_key_parser = get_cli_subparsers().add_parser('generate-api-key')
generate_api_key_parser.set_defaults(func=generate_api_key)
