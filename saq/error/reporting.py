from datetime import datetime
import logging
import os
import shutil
import sys
from typing import TYPE_CHECKING, Optional

from saq.configuration.config import get_config, get_engine_config
if TYPE_CHECKING:
    from saq.engine.execution_context import EngineExecutionContext
from saq.environment import get_data_dir
from saq.monitor import emit_monitor
from saq.monitor_definitions import MONITOR_ERROR_REPORT


def report_exception(execution_context: Optional["EngineExecutionContext"]=None):

    exc_type, reported_exception, tb = sys.exc_info()

    try:
        output_dir = os.path.join(get_data_dir(), get_config().global_settings.error_reporting_dir)
        error_report_path = os.path.join(output_dir, datetime.now().strftime('%Y-%m-%d:%H:%M:%S.%f'))
        with open(error_report_path, 'w') as fp:
            if execution_context:
                fp.write("CURRENT ANALYSIS TARGET: {}\n".format(execution_context.root))
                if execution_context.root:
                    fp.write("CURRENT ANALYSIS MODE: {}\n".format(execution_context.root.analysis_mode))

            fp.write("EXCEPTION\n")
            fp.write(str(reported_exception))
            fp.write("\n\nSTACK TRACE\n")

            from saq.error.formatter import ExceptionFormatter
            formatter = ExceptionFormatter()
            stack_trace, final_source = formatter.format_traceback(tb)

            fp.write(stack_trace)
            fp.write("\n\nEXCEPTION SOURCE\n")
            fp.write(final_source)
            fp.write("\n")

        emit_monitor(MONITOR_ERROR_REPORT, {
            "current_analysis_target": str(execution_context.root) if execution_context else None,
            "current_analysis_mode": str(execution_context.root.analysis_mode) if execution_context and execution_context.root else None,
            "exception": str(reported_exception),
            "stack_trace": stack_trace,
            "exception_source": final_source,
        })

        if get_engine_config().copy_analysis_on_error:
            if execution_context:
                if os.path.isdir(execution_context.root.storage_dir):
                    analysis_dir = '{}.ace'.format(error_report_path)
                    try:
                        shutil.copytree(execution_context.root.storage_dir, analysis_dir)
                        logging.warning("copied analysis from {} to {} for review".format(execution_context.root.storage_dir, analysis_dir))
                    except Exception as e:
                        logging.error("unable to copy from {} to {}: {}".format(execution_context.root.storage_dir, analysis_dir, e))

        return error_report_path

    except Exception as e:
        logging.error("uncaught exception when reporting an exception: {}".format(e))
        return None