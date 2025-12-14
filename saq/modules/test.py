# vim: sw=4:ts=4:et:cc=120
#
# collection of modules used for unit testing
#

import datetime
import logging
import os
import os.path
import time
from typing import Type

from pydantic import Field

from saq.analysis import Analysis
from saq.analysis.observable import Observable
from saq.configuration.config import get_config
from saq.constants import F_FILE, F_TEST, F_URL, F_USER, R_DOWNLOADED_FROM, VALID_OBSERVABLE_TYPES, AnalysisExecutionResult
from saq.environment import get_temp_dir
from saq.modules import AnalysisModule
from saq.modules.config import AnalysisModuleConfig
from tests.saq.helpers import recv_test_message, send_test_message

KEY_TEST_RESULT = 'test_result'
KEY_ACTUAL_VALUE = 'actual'
KEY_EXPECTED_VALUE = 'expected'
KEY_COMPLETE_TIME = 'complete_time'
KEY_INITIAL_REQUEST = 'initial_request'
KEY_DELAYED_REQUEST = 'delayed_request'
KEY_REQUEST_COUNT = 'request_count'

class TestAnalysis(Analysis):
    @property
    def test_result(self):
        return self.details[KEY_TEST_RESULT]

class BasicTestAnalysis(TestAnalysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { KEY_TEST_RESULT: True }

    def generate_summary(self):
        return "This is a summary."

class BasicTestAnalyzer(AnalysisModule):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.watched_file_path = os.path.join(get_temp_dir(), 'watched_file')
        with open(self.watched_file_path, 'w') as fp:
            fp.write('test1')

        self.watch_file(self.watched_file_path, self.watched_file_modified)

    def watched_file_modified(self ):
        logging.info(f"watched_file_modified: {self.watched_file_path}")

    @property
    def generated_analysis_type(self):
        return BasicTestAnalysis

    @property
    def valid_observable_types(self):
        return [ F_TEST, F_FILE ]

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        # I know this kind of logic is terrible
        if test.type == F_FILE and test.file_name != 'test_worker_timeout':
            return self.execute_file_analysis(test)
        elif test.value == 'test_1':
            return self.execute_analysis_1(test)
        elif test.value == 'test_2':
            return self.execute_analysis_2(test)
        elif test.value == 'test_3':
            return self.execute_analysis_3(test)
        elif test.value == 'test_4':
            return self.execute_analysis_4(test)
        elif test.value == 'test_5':
            return self.execute_analysis_5(test) # pyright: ignore
        elif test.value == 'test_6':
            return self.execute_analysis_6(test)
        elif test.value == 'test_7' or test.value == 'test_detection':
            return self.execute_analysis_7(test)
        elif test.value == 'test_8':
            return self.execute_analysis_8(test)
        elif test.value == 'test_worker_death':
            return self.execute_analysis_worker_death(test)
        elif test.value == 'test_worker_timeout' or (test.type == F_FILE and test.file_name == "test_worker_timeout"):
            return self.execute_analysis_worker_timeout(test)
        elif test.value.startswith('test_action_counter'):
            return self.execute_analysis_test_action_counter(test)
        elif test.value == 'test_add_file':
            return self.execute_analysis_test_add_file(test)
        elif test.value == 'test_add_large_file':
            return self.execute_analysis_test_add_large_file(test)
        elif test.value == 'test_watched_file':
            return self.execute_test_watched_file(test)
        elif test.value == 'test_memory_limit_warning':
            return self.execute_test_memory_limit_warning(test)
        elif test.value == 'test_memory_limit_kill':
            return self.execute_test_memory_limit_kill(test)
        elif test.value == 'test_pause':
            return self.execute_test_pause(test)
        elif test.value == 'test_cancel':
            return self.execute_test_cancel(test)
        else:
            return AnalysisExecutionResult.COMPLETED

    def execute_file_analysis(self, _file) -> AnalysisExecutionResult:
        raise RuntimeError("testing failure case")

    def execute_analysis_1(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_2(self, test) -> AnalysisExecutionResult:
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_3(self, test) -> AnalysisExecutionResult:
        pass # <-- intentional

    def execute_analysis_4(self, test) -> AnalysisExecutionResult:
        time.sleep(0.1) # take too long
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_6(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        new_observable = analysis.add_observable_by_spec(F_TEST, 'result_1')
        # exclude by instance
        new_observable.exclude_analysis(self)

        new_observable = analysis.add_observable_by_spec(F_TEST, 'result_2')
        # exclude by type
        new_observable.exclude_analysis(BasicTestAnalyzer)
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_7(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        analysis.add_detection_point('test detection')
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_8(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        analysis.add_detection_point('test detection')
        test.whitelist()
        self.get_root().whitelisted = True
        return AnalysisExecutionResult.COMPLETED
    
    def execute_analysis_test_action_counter(self, test) -> AnalysisExecutionResult:
        if self.get_root().get_action_counter('test') >= 2:
            return AnalysisExecutionResult.COMPLETED

        self.get_root().increment_action_counter('test')
        analysis = self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_worker_death(self, test) -> AnalysisExecutionResult:
        logging.info("execute_worker_death")
        os._exit(1)

    def execute_analysis_worker_timeout(self, test) -> AnalysisExecutionResult:
        logging.info("execute_worker_timeout")

        # CPU spin should cause Worker parent to kill it
        while True:
            pass

    def execute_analysis_test_add_file(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        path = self.get_root().create_file_path('test.txt')
        with open(path, 'w') as fp:
            fp.write("hello, world")

        analysis.add_file_observable(path)

        #os.mkdir(os.path.join(self.get_root().storage_dir, 'subdir'))
        #path = os.path.join(self.get_root().storage_dir, 'subdir', 'test2.txt')
        path_2 = self.get_root().create_file_path("test2.txt")
        with open(path_2, 'w') as fp:
            fp.write("Hello, world, 2!")
    
        analysis.add_file_observable(path_2, target_path="subdir/test2.txt")
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_test_add_large_file(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        path = self.get_root().create_file_path('test_large.txt')
        with open(path, 'wb') as fp:
            fp.write(os.urandom(1024 * 1024))

        analysis.add_file_observable(path)
        return AnalysisExecutionResult.COMPLETED

    def execute_test_watched_file(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

    def execute_test_memory_limit_warning(self, test) -> AnalysisExecutionResult:
        chunk = bytearray((get_config().global_settings.memory_limit_warning * 1024 * 1024) + 1)
        time.sleep(3)
        return AnalysisExecutionResult.COMPLETED

    def execute_test_memory_limit_kill(self, test) -> AnalysisExecutionResult:
        chunk = bytearray((get_config().global_settings.memory_limit_kill * 1024 * 1024) + 1024)
        time.sleep(3)
        return AnalysisExecutionResult.COMPLETED

    def execute_test_pause(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        time.sleep(3)
        return AnalysisExecutionResult.COMPLETED

    def execute_test_cancel(self, test) -> AnalysisExecutionResult:
        self.cancel_analysis()
        return AnalysisExecutionResult.COMPLETED

class ConfigurableModuleTestAnalysis(TestAnalysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { KEY_TEST_RESULT: True }

    def generate_summary(self):
        return "This is a summary."

class ConfigurableModuleTestAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return ConfigurableModuleTestAnalysis

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

class BadSummaryTestAnalysis(TestAnalysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { KEY_TEST_RESULT: True }

    def generate_summary(self):
        return f"This is a bad summary becuase there is {self['no_such_key']}"

class BadSummaryTestAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return BadSummaryTestAnalysis

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

class GenericTestAnalysis(TestAnalysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { 'Hello': 'world!' }

    def generate_summary(self):
        return str(self.observable.value)

class GenericTestAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return GenericTestAnalysis

    @property
    def valid_observable_types(self):
        return VALID_OBSERVABLE_TYPES

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        analysis = self.create_analysis(observable)
        return AnalysisExecutionResult.COMPLETED

class ValidQueueAnalysis(TestAnalysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { "success": True }

    def generate_summary(self):
        return ""

class ValidQueueAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return ValidQueueAnalysis

    @property
    def valid_observable_types(self):
        return VALID_OBSERVABLE_TYPES

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        analysis = self.create_analysis(observable)
        return AnalysisExecutionResult.COMPLETED

class InvalidQueueAnalysis(TestAnalysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { "success": True }

    def generate_summary(self):
        return ""

class InvalidQueueAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return InvalidQueueAnalysis

    @property
    def valid_observable_types(self):
        return VALID_OBSERVABLE_TYPES

    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        analysis = self.create_analysis(observable)
        return AnalysisExecutionResult.COMPLETED

class PauseAnalysis(TestAnalysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { }

class PauseAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return PauseAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        if test.value.startswith('pause_'):
            seconds = int(test.value[len('pause_'):])
            time.sleep(seconds)

        return AnalysisExecutionResult.COMPLETED

class MergeTestAnalysis(TestAnalysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { KEY_TEST_RESULT: True }

class MergeTestAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return MergeTestAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        if test.value == 'merge_test_1':
            return self.execute_analysis_1(test)
        else:
            return AnalysisExecutionResult.COMPLETED

    def execute_analysis_1(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        output_observable = analysis.add_observable_by_spec(F_TEST, 'test_output')
        output_observable.add_tag('test')

        output_path = self.get_root().create_file_path('sample.txt')
        with open(output_path, 'w') as fp:
            fp.write('test')

        file_observable = analysis.add_file_observable(output_path)
        url_observable = analysis.add_observable_by_spec(F_URL, 'http://google.com')
        file_observable.add_relationship(R_DOWNLOADED_FROM, url_observable)

        # we also add an existing observable
        user_observable = analysis.add_observable_by_spec(F_USER, 'admin')
        return AnalysisExecutionResult.COMPLETED

KEY_SUCCESS = 'success'
KEY_FAIL = 'fail'
KEY_BY_MODULE_ID = 'module_id'

class DependencyTestAnalysis(TestAnalysis):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_SUCCESS: {
                KEY_BY_MODULE_ID: None,
            },
            KEY_FAIL: {
                KEY_BY_MODULE_ID: None,
            },
        }

class DependencyTestAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return DependencyTestAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)

        analysis.details[KEY_SUCCESS][KEY_BY_MODULE_ID] = self._context.configuration_manager.is_module_enabled("dependency_test")
        analysis.details[KEY_FAIL][KEY_BY_MODULE_ID] = self._context.configuration_manager.is_module_enabled("basic_test")

        return AnalysisExecutionResult.COMPLETED

class DelayedAnalysisTestAnalysis(TestAnalysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = {
            KEY_INITIAL_REQUEST: True,
            KEY_DELAYED_REQUEST: False,
            KEY_REQUEST_COUNT: 1,
            KEY_COMPLETE_TIME: None,
        }
        
    @property
    def complete_time(self):
        return self.details[KEY_COMPLETE_TIME]

    @property
    def initial_request(self):
        return self.details[KEY_INITIAL_REQUEST]

    @property
    def delayed_request(self):
        return self.details[KEY_DELAYED_REQUEST]

    @property
    def request_count(self):
        return self.details[KEY_REQUEST_COUNT]

class DelayedAnalysisTestModule(AnalysisModule):
    
    @property
    def generated_analysis_type(self):
        return DelayedAnalysisTestAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        # the observable value is the format M:SS|M:SS
        delay, timeout = test.value.split('|')
        delay_minutes, delay_seconds = map(int, delay.split(':'))
        timeout_minutes, timeout_seconds = map(int, timeout.split(':'))
        return self.delay_analysis(test, analysis, minutes=delay_minutes, seconds=delay_seconds, 
                                    timeout_minutes=timeout_minutes, timeout_seconds=timeout_seconds)

    def continue_analysis(self, observable: Observable, analysis: Analysis) -> AnalysisExecutionResult:
        assert isinstance(observable, Observable)
        assert isinstance(analysis, Analysis)

        analysis.details[KEY_DELAYED_REQUEST] = True
        analysis.details[KEY_REQUEST_COUNT] += 1
        analysis.details[KEY_COMPLETE_TIME] = datetime.datetime.now()
        return AnalysisExecutionResult.COMPLETED

class EngineLockingTestAnalysis(Analysis):
    pass

class EngineLockingTestModule(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return EngineLockingTestAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, t) -> AnalysisExecutionResult:
        analysis = self.create_analysis(t)
        # let the main process know we're executing now
        send_test_message('ok')
        # wait for main process to say we're good to go
        result = recv_test_message()
        return AnalysisExecutionResult.COMPLETED

class FinalAnalysisTestAnalysis(TestAnalysis):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.details = { KEY_TEST_RESULT: True }

class FinalAnalysisTestAnalyzer(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return FinalAnalysisTestAnalysis

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        return AnalysisExecutionResult.INCOMPLETE

    def execute_final_analysis(self, test):
        analysis = self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

class PostAnalysisTestResult(TestAnalysis):
    pass

class PostAnalysisTest(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return PostAnalysisTestResult

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        if test.value == 'test_delayed':
            return self.execute_analysis_delayed(test)
        else:
            return self.execute_analysis_default(test)

    def continue_analysis(self, observable: Observable, analysis: Analysis) -> AnalysisExecutionResult:
        assert isinstance(observable, Observable)
        assert isinstance(analysis, Analysis)

        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_delayed(self, test):
        analysis = self.create_analysis(test)
        return self.delay_analysis(test, analysis, seconds=0)

    def execute_analysis_default(self, *args, **kwargs) -> AnalysisExecutionResult:
        return AnalysisExecutionResult.COMPLETED

    def execute_post_analysis(self):
        logging.info("execute_post_analysis called")
        return AnalysisExecutionResult.COMPLETED

class PostAnalysisMultiModeTestResult(TestAnalysis):
    pass

class PostAnalysisMultiModeTest(AnalysisModule):
    @property
    def generated_analysis_type(self):
        return PostAnalysisMultiModeTestResult

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        return AnalysisExecutionResult.COMPLETED

    def execute_post_analysis(self):
        logging.info("execute_post_analysis called")
        if self.get_root().analysis_mode == 'test_groups':
            self.get_root().analysis_mode = 'test_single'
            return AnalysisExecutionResult.INCOMPLETE

        if self.get_root().analysis_mode == 'test_single':
            self.get_root().analysis_mode = 'test_empty'
            return AnalysisExecutionResult.INCOMPLETE

        return AnalysisExecutionResult.COMPLETED

class DelayedAnalysisTimeoutTestResult(TestAnalysis):
    pass

class DelayedAnalysisTimeoutTest(AnalysisModule):
    
    @property
    def generated_analysis_type(self):
        return DelayedAnalysisTimeoutTestResult

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)

        # the observable value is the format M:SS|M:SS
        delay, timeout = test.value.split('|')
        delay_minutes, delay_seconds = map(int, delay.split(':'))
        timeout_minutes, timeout_seconds = map(int, timeout.split(':'))
        return self.delay_analysis(test, analysis, minutes=delay_minutes, seconds=delay_seconds, 
                                   timeout_minutes=timeout_minutes, timeout_seconds=timeout_seconds)

    def continue_analysis(self, observable: Observable, analysis: Analysis) -> AnalysisExecutionResult:
        assert isinstance(observable, Observable)
        assert isinstance(analysis, Analysis)

        delay, timeout = observable.value.split('|')
        delay_minutes, delay_seconds = map(int, delay.split(':'))
        timeout_minutes, timeout_seconds = map(int, timeout.split(':'))
        return self.delay_analysis(observable, analysis, minutes=delay_minutes, seconds=delay_seconds, 
                                   timeout_minutes=timeout_minutes, timeout_seconds=timeout_seconds)

class WaitAnalysis_A(Analysis):
    pass

class WaitAnalyzerModule_A(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return WaitAnalysis_A

    @property
    def valid_observable_types(self):
        return F_TEST

    # XXX this is a mess
    # we need to get rid of this whole thing where we are using the test value
    # to determine the analysis to run
    def execute_analysis(self, test) -> AnalysisExecutionResult:
        if test.value == 'test_1':
            return self.execute_analysis_01(test)
        elif test.value == 'test_2':
            return self.execute_analysis_02(test)
        elif test.value == 'test_3':
            return self.execute_analysis_03(test)
        elif test.value == 'test_4':
            return self.execute_analysis_04(test)
        elif test.value == 'test_5':
            return self.execute_analysis_05(test)
        elif test.value == 'test_6':
            return self.execute_analysis_06(test)
        elif test.value == 'test_7':
            return self.execute_analysis_07(test)
        elif test.value == 'test_8':
            return self.execute_analysis_08(test)
        elif test.value == 'test_engine_032a':
            return self.execute_analysis_test_engine_032a(test)
        elif test.value == 'test_wait_for_analysis_source_delayed':
            return self.execute_analysis_wait_for_analysis_source_delayed(test)
        elif test.value == 'test_wait_for_analysis_source_and_target_delayed':
            return self.execute_analysis_wait_for_analysis_source_and_target_delayed(test)

    def continue_analysis(self, observable: Observable, analysis: Analysis) -> AnalysisExecutionResult:
        assert isinstance(observable, Observable)
        assert isinstance(analysis, Analysis)

        return AnalysisExecutionResult.COMPLETED
        
    def execute_analysis_01(self, test) -> AnalysisExecutionResult:
        # NOTE the execution order of modules is alphabetically by the config section name of the module
        analysis = self.wait_for_analysis(test, WaitAnalysis_B)
        if not analysis:
            return AnalysisExecutionResult.COMPLETED

        self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_02(self, test) -> AnalysisExecutionResult:
        self.wait_for_analysis(test, WaitAnalysis_B)
        self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_03(self, test) -> AnalysisExecutionResult:
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_04(self, test) -> AnalysisExecutionResult:
        self.wait_for_analysis(test, WaitAnalysis_B)
        self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_05(self, test) -> AnalysisExecutionResult:
        self.wait_for_analysis(test, WaitAnalysis_B)
        self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_06(self, test) -> AnalysisExecutionResult:
        self.wait_for_analysis(test, WaitAnalysis_B)
        self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_test_engine_032a(self, test) -> AnalysisExecutionResult:
        self.wait_for_analysis(test, WaitAnalysis_B)
        self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_07(self, test) -> AnalysisExecutionResult:
        # NOTE the execution order of modules is alphabetically by the config section name of the module
        analysis = self.wait_for_analysis(test, WaitAnalysis_B, instance='instance1')
        if not analysis:
            return AnalysisExecutionResult.COMPLETED

        self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_08(self, test) -> AnalysisExecutionResult:
        if self.instance == 'instance1':
            analysis = self.wait_for_analysis(test, WaitAnalysis_A, instance='instance2')
            if not analysis:
                return AnalysisExecutionResult.COMPLETED

            self.create_analysis(test)
            return AnalysisExecutionResult.COMPLETED

        elif self.instance == 'instance2':
            self.create_analysis(test)
            return AnalysisExecutionResult.COMPLETED

    def execute_analysis_wait_for_analysis_source_delayed(self, test) -> AnalysisExecutionResult:
        # start waiting for B
        self.wait_for_analysis(test, WaitAnalysis_B)
        analysis = self.create_analysis(test)

        # and then start to delay
        return self.delay_analysis(test, analysis, seconds=2)

    def execute_analysis_wait_for_analysis_source_and_target_delayed(self, test) -> AnalysisExecutionResult:
        # start waiting for B
        self.wait_for_analysis(test, WaitAnalysis_B)
        analysis = self.create_analysis(test)

        # and then start to delay
        return self.delay_analysis(test, analysis, seconds=2)

class WaitAnalysis_B(Analysis):
    pass

class WaitAnalyzerModule_B(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return WaitAnalysis_B

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        if test.value == 'test_1':
            return self.execute_analysis_01(test)
        elif test.value == 'test_2':
            return self.execute_analysis_02(test)
        elif test.value == 'test_3':
            return self.execute_analysis_03(test)
        elif test.value == 'test_4':
            return self.execute_analysis_04(test)
        elif test.value == 'test_5':
            return self.execute_analysis_05(test)
        elif test.value == 'test_6':
            return self.execute_analysis_06(test)
        elif test.value == 'test_7':
            return self.execute_analysis_07(test)
        elif test.value == 'test_wait_for_analysis_source_delayed':
            #return self.execute_analysis_wait_for_analysis_source_delayed(test)
            return self.execute_analysis_01(test)
        elif test.value == 'test_wait_for_analysis_source_and_target_delayed':
            return self.execute_analysis_wait_for_analysis_source_and_target_delayed(test)

    def execute_analysis_01(self, test) -> AnalysisExecutionResult:
        self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_02(self, test) -> AnalysisExecutionResult:
        self.wait_for_analysis(test, WaitAnalysis_A)
        self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_03(self, test) -> AnalysisExecutionResult:
        self.wait_for_analysis(test, WaitAnalysis_A)
        self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_04(self, test) -> AnalysisExecutionResult:
        self.wait_for_analysis(test, WaitAnalysis_C)
        self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_05(self, test) -> AnalysisExecutionResult:
        self.wait_for_analysis(test, WaitAnalysis_C)
        self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_06(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        return self.delay_analysis(test, analysis, seconds=2)

    def execute_analysis_07(self, test) -> AnalysisExecutionResult:
        self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_wait_for_analysis_source_and_target_delayed(self, test):
        analysis = self.create_analysis(test)
        return self.delay_analysis(test, analysis, seconds=2)

class WaitAnalysis_C(Analysis):
    pass

class WaitAnalyzerModule_C(AnalysisModule):

    @property
    def generated_analysis_type(self):
        return WaitAnalysis_C

    @property
    def valid_observable_types(self):
        return F_TEST

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        if test.value == 'test_4':
            return self.execute_analysis_04(test)
        elif test.value == 'test_5':
            return self.execute_analysis_05(test)
        elif test.value == 'test_engine_032a':
            return self.execute_analysis_test_engine_032a(test)

    def execute_analysis_04(self, test) -> AnalysisExecutionResult:
        self.wait_for_analysis(test, WaitAnalysis_A)
        self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_05(self, test) -> AnalysisExecutionResult:
        self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

    def execute_analysis_test_engine_032a(self, test) -> AnalysisExecutionResult:
        self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

class ForcedDetectionTestAnalysis(Analysis):
    pass

class ForcedDetectionTestAnalyzer(AnalysisModule):
    """Adds a detection point to every observable."""
    @property
    def valid_observable_types(self):
        return None

    @property
    def generated_analysis_type(self):
        return ForcedDetectionTestAnalysis
        
    def execute_analysis(self, observable) -> AnalysisExecutionResult:
        analysis = self.create_analysis(observable)
        observable.add_detection_point("test")
        return AnalysisExecutionResult.COMPLETED

class CloudphishDelayedTestAnalysis(Analysis):
    pass

class CloudphishDelayedTestAnalyzer(AnalysisModule):
    @property
    def valid_observable_types(self):
        return F_URL

    @property
    def generated_analysis_type(self):
        return CloudphishDelayedTestAnalysis

    def execute_analysis(self, url) -> AnalysisExecutionResult:
        analysis = self.create_analysis(url)
        # cause a timeout in the cloudphish test
        time.sleep(5)
        return AnalysisExecutionResult.COMPLETED

class HighPriorityAnalysis(Analysis):
    pass

class HighPriorityAnalyzer(AnalysisModule):
    @property
    def valid_observable_types(self):
        return F_TEST

    @property
    def generated_analysis_type(self):
        return HighPriorityAnalysis

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

class GenerateFileAnalysis(Analysis):
    pass

class GenerateFileAnalyzer(AnalysisModule):
    @property
    def valid_observable_types(self):
        return F_TEST

    @property
    def generated_analysis_type(self):
        return GenerateFileAnalysis

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        target_path = self.get_root().create_file_path('test_worker_timeout')
        with open(target_path, 'w') as fp:
            fp.write("Hello, world!")

        analysis.add_file_observable(target_path)
        return AnalysisExecutionResult.COMPLETED

class LowPriorityAnalysis(Analysis):
    pass

class LowPriorityAnalyzer(AnalysisModule):
    @property
    def valid_observable_types(self):
        return F_TEST

    @property
    def generated_analysis_type(self):
        return LowPriorityAnalysis

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

class NoPriorityAnalysis(Analysis):
    pass

class NoPriorityAnalyzer(AnalysisModule):
    @property
    def valid_observable_types(self):
        return F_TEST

    @property
    def generated_analysis_type(self):
        return NoPriorityAnalysis

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

class GroupedByTimeRangeAnalysis(Analysis):
    pass

class GroupedByTimeRangeAnalyzer(AnalysisModule):
    @property
    def valid_observable_types(self):
        return F_TEST

    @property
    def generated_analysis_type(self):
        return GroupedByTimeRangeAnalysis

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

class GroupingTargetAnalysis(Analysis):
    pass

class GroupingTargetAnalyzer(AnalysisModule):
    @property
    def valid_observable_types(self):
        return F_TEST

    @property
    def generated_analysis_type(self):
        return GroupingTargetAnalysis

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        return AnalysisExecutionResult.COMPLETED

class TestInstanceConfig(AnalysisModuleConfig):
    sql: str = Field(..., description="the SQL to use for the analysis")

class TestInstanceAnalysis(Analysis):
    __test__ = False

class TestInstanceAnalyzer(AnalysisModule):
    @classmethod
    def get_config_class(cls) -> Type[AnalysisModuleConfig]:
        return TestInstanceConfig

    @property
    def sql(self):
        return self.config.sql

    @property
    def valid_observable_types(self):
        return F_TEST

    @property
    def generated_analysis_type(self):
        return TestInstanceAnalysis

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        analysis.details = { 'sql': self.sql }
        return AnalysisExecutionResult.COMPLETED

class FileSizeLimitAnalysis(Analysis):
    pass

class FileSizeLimitAnalyzer(AnalysisModule):
    @property
    def valid_observable_types(self):
        return F_FILE

    @property
    def generated_analysis_type(self):
        return FileSizeLimitAnalysis

    def execute_analysis(self, test) -> AnalysisExecutionResult:
        analysis = self.create_analysis(test)
        analysis.details = { 'hello': 'world' }
        return AnalysisExecutionResult.COMPLETED
