import datetime
import json
import logging
import os
import os.path
import shutil
import socket
import sys
import uuid

from saq.cli.cli_main import get_cli_subparsers
from saq.cli.cli_util import display_analysis
from saq.configuration import get_config
from saq.configuration.config import get_analysis_module_config
from saq.constants import F_FILE
from saq.environment import get_global_runtime_settings
from saq.engine.engine_configuration import EngineConfiguration
from saq.engine.enums import EngineExecutionMode, EngineType


def correlate(args):
    # initialize command line engine
    from saq.analysis import RootAnalysis
    from saq.constants import ANALYSIS_MODE_CLI, ANALYSIS_MODE_CORRELATION, \
        SUMMARY_DETAIL_FORMAT_TXT, SUMMARY_DETAIL_FORMAT_PRE, SUMMARY_DETAIL_FORMAT_MD
    from saq.engine.core import Engine
    from saq.util import parse_event_time


    if len(args.targets) % 2 != 0:
        logging.error("odd number of arguments (you need pairs of type and value)")
        sys.exit(1)

    targets = args.targets
    
    # did we specify targets from stdin?
    if args.from_stdin:
        for o_value in sys.stdin:
            # the type of observables coming in on stdin is also specified on the command line
            targets.append(args.stdin_type)
            targets.append(o_value.strip())

    reference_time = None
    if args.reference_time is not None:
        reference_time = parse_event_time(args.reference_time)

    if os.path.exists(args.storage_dir) and not args.load:
        # if the output directory is the default directory then just delete it
        # this has been what I've wanted to happen 100% of the time
        if args.storage_dir == 'ace.out':
            try:
                logging.warning("deleting existing output directory ace.out")
                shutil.rmtree('ace.out')
            except Exception as e:
                logging.error("unable to delete existing output directory ace.out: {}".format(e))
                sys.exit(1)
        else:
            logging.error("output directory {} already exists".format(args.storage_dir))
            sys.exit(1)

    # the list of root analyses to analyze
    roots: list[RootAnalysis] = []

    if args.uuid is not None:
        root_uuid = args.uuid
    else:
        root_uuid = str(uuid.uuid4())

    root = RootAnalysis(uuid=root_uuid, storage_dir=args.storage_dir)

    if os.path.exists(args.storage_dir):
        logging.warning("storage directory {} already exists".format(args.storage_dir))
    else:
        # create the output directory
        try:
            root.initialize_storage()
        except Exception as e:
            logging.error("unable to create output directory {}: {}".format(args.storage_dir, e))
            sys.exit(1)

    if args.load:
        root.load()

        # we override whatever previous analysis mode it had
        root.analysis_mode = ANALYSIS_MODE_CLI if args.analysis_mode is None else args.analysis_mode

    else:
        # set all of the properties individually
        # XXX only require company_id in RootAnalysis
        if args.company_name:
            root.company_name = args.company_name

        root.tool = 'ACE - Command Line Analysis'
        root.tool_instance = socket.gethostname()
        root.alert_type = args.alert_type
        root.analysis_mode = ANALYSIS_MODE_CLI if args.analysis_mode is None else args.analysis_mode
        analysis_mode_config = get_config().get_analysis_mode_config(root.analysis_mode)

        # disable cleanup in whatever mode we use
        analysis_mode_config.cleanup = False

        root.description = args.description if args.description else 'Command Line Correlation'
        root.instructions = args.instructions
        root.event_time = datetime.datetime.now() if reference_time is None else reference_time
        if args.load_details:
            with open(args.load_details, 'r') as fp:
                root.details = json.load(fp)
        else:
            root.details = {
                'comment': args.comment
            }

    # add any summary details specified on the command line
    if args.summary_details:
        valid_formats = [SUMMARY_DETAIL_FORMAT_TXT, SUMMARY_DETAIL_FORMAT_PRE, SUMMARY_DETAIL_FORMAT_MD]
        for sd_args in args.summary_details:
            if len(sd_args) < 1 or len(sd_args) > 3:
                logging.error("--add-summary-detail requires 1 to 3 values (CONTENT or HEADER CONTENT [FORMAT]), got %s", len(sd_args))
                sys.exit(1)

            if len(sd_args) == 1:
                header = None
                content = sd_args[0]
                sd_format = SUMMARY_DETAIL_FORMAT_TXT
            else:
                header = sd_args[0]
                content = sd_args[1]
                sd_format = sd_args[2] if len(sd_args) == 3 else SUMMARY_DETAIL_FORMAT_TXT

            if sd_format not in valid_formats:
                logging.error("invalid summary detail format '%s', must be one of: %s", sd_format, ", ".join(valid_formats))
                sys.exit(1)

            root.add_summary_detail(header=header, content=content, format=sd_format)

    # create the list of observables to add to the alert for analysis
    index = 0
    while index < len(args.targets):
        o_type = args.targets[index]
        o_value = args.targets[index + 1]

        # the root analysis we're currently working on (defaults to the main alert)
        current_root = root

        # are we creating a separate alert for each observable?
        if args.split:
            subdir = os.path.join(root.storage_dir, current_root.uuid[0:3])
            if not os.path.exists(subdir):
                try:
                    os.mkdir(subdir)
                except Exception as e:
                    logging.error("unable to create directory {}: {}".format(subdir, e))
                    sys.exit(1)

            current_root = RootAnalysis(storage_dir=os.path.join(subdir, current_root.uuid))
            try:
                current_root.initialize_storage()
            except Exception as e:
                logging.error("unable to create directory {}: {}".format(subdir, e))

            # XXX not sure we need this any more
            # we'll make a little symlink if we can to help analysts know which directory is what
            # it's ok if this fails
            try:
                os.symlink(os.path.join(current_root.uuid[0:3], current_root.uuid), os.path.join(root.storage_dir, str(o_value)))
            except Exception as e:
                logging.warning("unable to create symlink: {}".format(e))

            current_root.tool = root.tool
            current_root.tool_instance = root.tool_instance
            current_root.alert_type = root.alert_type
            current_root.analysis_mode = root.analysis_mode
            current_root.description = "{} - {}:{}".format(root.description, o_type, o_value)
            current_root.event_time = root.event_time
            current_root.details = root.details
            current_root.summary_details = list(root.summary_details)

        if o_type == F_FILE:
            observable = current_root.add_file_observable(o_value, volatile=args.volatile)
        else:
            observable = current_root.add_observable_by_spec(o_type, o_value, reference_time, volatile=args.volatile)

        if observable is not None:
            for directive in args.directives:
                observable.add_directive(directive)

            for tag in args.tags:
                observable.add_tag(tag)

        index += 2

        if args.split:
            current_root.save()
            roots.append(current_root)

    # if we are not splitting up the alerts then we just have one alert to look at
    if not args.split:
        root.save()
        roots.append(root)

    engine = Engine(config = EngineConfiguration(engine_type=EngineType.LOCAL, single_threaded_mode=not args.multi_threaded))
    engine.configuration_manager.config.alerting_enabled = False
    worker = engine.initialize_single_threaded_worker()

    for root in roots:
        worker.workload_manager.add_workload(root)

    # allow the user to control what analysis modules run
    if args.disable_all:
        logging.warning("disabling all analysis modules...")
        for analysis_module_config in get_config().analysis_modules:
            analysis_module_config.enabled = False

    if args.disabled_modules:
        for module_name in args.disabled_modules:
            analysis_module_config = get_analysis_module_config(module_name)
            logging.warning("disabling {}".format(module_name))
            analysis_module_config.enabled = False

    # enable by group
    if args.enable_module_group:
        for module_group in args.enable_module_group:
            module_group_config = get_config().get_module_group_config(module_group)
            for module_name in module_group_config.modules:
                analysis_module_config = get_analysis_module_config(module_name)
                logging.info("enabling {} by group {}".format(module_name, module_group))
                analysis_module_config.enabled = True

    if args.enabled_modules:
        for module_name in args.enabled_modules:
            logging.info("enabling {}".format(module_name))
            get_analysis_module_config(module_name).enabled = True
            engine.configuration_manager.enable_module(module_name, ANALYSIS_MODE_CLI)

    try:
        engine.start_single_threaded(execution_mode=EngineExecutionMode.UNTIL_COMPLETE)
    except KeyboardInterrupt:
        logging.warning("user interrupted correlation")

    for root in roots:
        # display the results
        root = RootAnalysis(storage_dir=root.storage_dir)
        root.load()
        display_analysis(root, include_context=True)

        if args.alert or args.submit_alerts_local:
            if root.whitelisted:
                logging.info("{} was whitelisted".format(root))
                continue

            if args.force or get_global_runtime_settings().forced_alerts or root.has_detections():
                # need to switch the mode to correlation
                root.analysis_mode = ANALYSIS_MODE_CORRELATION
                root.save()

                if args.submit_alerts_local:
                    from saq.database.util.alert import ALERT

                    try:
                        logging.info("submitting {} as local alert".format(root))
                        new_root = root.duplicate()
                        new_root.move(storage_dir_from_uuid(new_root.uuid))
                        new_root.save()
                        ALERT(new_root)
                        new_root.schedule()
                    except Exception as e:
                        logging.error("unable to submit local alert {}: {}".format(root, e))
                else:
                    from ace_api import upload
                    try:
                        logging.info("uploading {}".format(root))

                        remote_host = None # if left as None then the api call defaults it to ace_api.default_node
                        if args.remote_host is not None:
                            remote_host = args.remote_host

                        if args.remote_port is not None:
                            remote_host = '{}:{}'.format(remote_host, args.remote_port)

                        result = upload(root.uuid, root.storage_dir, remote_host=remote_host, ssl_verification=args.ssl_ca_path)

                    except Exception as e:
                        logging.error("unable to upload {}: {}".format(root, e))

    sys.exit(0)

correlate_parser = get_cli_subparsers().add_parser('correlate',
    help="Analyze one or more observables or alerts.",
    epilog="Example: ace correlate ipv4 8.8.8.8 -G email -E ip_inspector -E gglsbl_service -D process_analysis_v1 -G common")
correlate_parser.add_argument('--multi-threaded', required=False, dest='multi_threaded', default=False, action='store_true',
    help="Use multiple processes to run the analysis.")
correlate_parser.add_argument('-D', '--disable-module', required=False, dest='disabled_modules', action='append',
    help="Specify a module name (substring match) to disable. This option can be specified multiple times.")
correlate_parser.add_argument('--disable-all', required=False, dest='disable_all', default=False, action='store_true',
    help="Disable all analysis modules (use -E switch to enable specific modules.")
correlate_parser.add_argument('-E', '--enable-module', required=False, dest='enabled_modules', action='append', 
    help="Specify module names (substring match) to enable. This option can be specified multiple times.")
correlate_parser.add_argument('-G', '--enable-module-group', required=False, dest='enable_module_group', action='append',
    help="Module groups to enable by name. Specify for each module group.")
correlate_parser.add_argument('-m', '--analysis-mode', required=False, dest='analysis_mode', 
    help="The analysis mode to use for this analysis. Defaults to cli")
correlate_parser.add_argument('-d', '--storage-dir', required=False, dest='storage_dir', default='ace.out',
    help="Specify an output directory.  Defaults to ace.out.")
correlate_parser.add_argument('-t', '--reference-time', required=False, dest='reference_time', default=None,
    help="Specify a datetime in YYYY-MM-DD HH:MM:SS [+-]0000 format that observables (of a temporal type) should be referenced from.")
correlate_parser.add_argument('--description', required=False, dest='description', default="ACE Manual Correlation",
    help="Supply a description.  This will be displayed as part of the alert if this correlation is later imported as an alert.")
correlate_parser.add_argument('--comment', required=False, dest='comment', default=None,
    help="Optional generic comment to add to the details of the alert.")
correlate_parser.add_argument('--add-directive', required=False, dest='directives', action='append', default=[],
    help="Adds the given directive to all observables specified.  This option can be used multiple times.")
correlate_parser.add_argument('--add-tag', required=False, dest='tags', action='append', default=[],
    help="Adds the given tag to all observables specified.  This option can be used multiple times.")
correlate_parser.add_argument('--volatile', required=False, dest='volatile', action='store_true', default=False,
    help="Adds the observables as volatile obervables.")
correlate_parser.add_argument('--alert-type', required=False, dest='alert_type', default='cli_analysis',
    help="Optionally set the alert type.  Some analysis is only performed for alerts of a certain type.")
correlate_parser.add_argument('--instructions', required=False, dest='instructions', default=None,
    help="""A free form string value that gives the analyst instructions on what
        this alert is about and/or how to analyze the data contained in the
        alert.""")
correlate_parser.add_argument('--company-name', required=False, dest='company_name', default=None,
    help="Optionally assign ownership of this analysis to a company.")
correlate_parser.add_argument('--alert', required=False, dest='alert', action='store_true', default=False,
    help="Insert the correlation as an alert if it contains a detection point. Uploads to a remote ACE instance.")
correlate_parser.add_argument('--submit-alerts-local', required=False, dest='submit_alerts_local', action='store_true', default=False,
    help="Submit as alerts to the local ACE instance if the correlation contains a detection point.")
correlate_parser.add_argument('--force', required=False, dest='force', action='store_true', default=False,
    help="Force alert creation even if no detection points are found. Use with --alert or --submit-alerts-local.")
correlate_parser.add_argument('--remote-host', required=False, dest='remote_host', default=None,
    help="Specify the remote host of the ACE system (defaults to the engine_ace configuration values).")
correlate_parser.add_argument('--remote-port', required=False, dest='remote_port', default=None, type=int,
    help="Specify the remote port of the ACE system (defaults to the engine_ace configuration values).")
#correlate_parser.add_argument('--ssl-root-cert', required=False, dest='ssl_root_cert', default=None,
    #help="Specify the path to the SSL cert for the ACE system (defaults to the engine_ace configuration values).")
#correlate_parser.add_argument('--ssl-key', required=False, dest='ssl_key', default=None,
    #help="Specify the path to the SSL key for the ACE system (defaults to the engine_ace configuration values).")
correlate_parser.add_argument('--ssl-ca-path', required=False, dest='ssl_ca_path', default=None,
    help="Specify the path to the CA cert for the ACE system (defaults to the engine_ace configuration values).")
#correlate_parser.add_argument('--ssl-hostname', required=False, dest='ssl_hostname', default=None,
    #help="Specify the ssl hostname of the ACE system (defaults to the engine_ace configuration values).")
correlate_parser.add_argument('--split', required=False, dest='split', action='store_true', default=False,
    help="Split the observables up into individual analysis.")
correlate_parser.add_argument('--from-stdin', required=False, dest='from_stdin', action='store_true', default=False,
    help="Read observables from stanard input.  Defaults to treating them as file-type observables.")
correlate_parser.add_argument('--stdin-type', required=False, dest='stdin_type', default='file',
    help="Specify the observable type when reading observables from stdin. Defaults to file.")
#correlate_parser.add_argument('--skip-analysis', required=False, dest='skip_analysis', action='store_true', default=False,
    #help="Skip analyzing the alert. Useful if you just want to send a bunch of stuff to ACE for analysis.")
correlate_parser.add_argument('--load', required=False, dest='load', action='store_true', default=False,
    help="Instead of creating a new analysis, load the existing analysis stored at --storage-dir.")
correlate_parser.add_argument('--load-details', required=False, dest='load_details', default=None,
    help="Load the given JSON file as the details of the alert.")
correlate_parser.add_argument('--add-summary-detail', required=False, dest='summary_details',
    action='append', nargs='+', metavar='VALUE',
    help="Add a summary detail to the root analysis. Specify as: CONTENT, HEADER CONTENT, or HEADER CONTENT FORMAT. "
         "HEADER is optional. FORMAT is optional and defaults to 'txt'. Valid formats are 'txt' and 'pre'. "
         "This option can be specified multiple times.")
correlate_parser.add_argument('--uuid', required=False, dest='uuid', default=None,
    help="Use this uuid as the uuid of the temporary root analysis. Defaults to random if not specified.")
correlate_parser.add_argument('targets', nargs="*",
    help="One or more pairs of indicator types and values.")
correlate_parser.set_defaults(func=correlate)
