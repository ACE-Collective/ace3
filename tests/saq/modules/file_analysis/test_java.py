
import os
import pytest

from saq.modules.file_analysis.java import decompile_java_class_file


@pytest.mark.unit
def test_decompile_java_class_file(tmp_path, datadir):
    class_file = str(datadir / 'VxUGJsAplRNavewkjKujp.class')
    assert os.path.exists(class_file)

    java_file = decompile_java_class_file(class_file)
    assert os.path.getsize(java_file) > 0

    with open(java_file) as fp:
        java_code = fp.read()
        assert 'HBrowserNativeApis.PygDMDiPgHIHFKYIMuHMd' in java_code

    # if we do it a second time we'll get a different file name
    java_file_2 = decompile_java_class_file(class_file)
    assert os.path.exists(java_file_2)
    assert java_file_2 != java_file

    # if we pass a missing file we get None back
    assert decompile_java_class_file('does_not_exist.java') is None

    # if we pass something that is not a java class file we get None back
    not_class_file = tmp_path / 'not_a_class_file.class'
    not_class_file.write_text("This is not a class file.")
    not_class_file = str(not_class_file)

    assert decompile_java_class_file(not_class_file) is None