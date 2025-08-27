import pytest

from saq.modules.file_analysis.archive import order_archive_file_list


class TestOrderArchiveFileList:
    
    @pytest.mark.unit
    @pytest.mark.parametrize("file_list,expected", [
        # edge cases
        ([], []),
        (["file1.txt"], ["file1.txt"]),
        (["file1.txt", "file2.txt"], ["file1.txt", "file2.txt"]),
        
        # sorting by priority
        (["file1.exe", "file2.txt", "file3.pdf"], ["file1.exe", "file3.pdf", "file2.txt"]),
        
        # attack extensions (priority 0) - highest priority
        (["file1.txt", "file2.lnk", "file3.exe", "file4.one", "file5.pdf"], 
         ["file2.lnk", "file4.one", "file3.exe", "file5.pdf", "file1.txt"]),
        (["file1.jnlp", "file2.iso", "file3.img", "file4.vhd", "file5.txt"],
         ["file1.jnlp", "file2.iso", "file3.img", "file4.vhd", "file5.txt"]),
        (["file1.vhdx", "file2.vmdk", "file3.msi", "file4.hta", "file5.txt"],
         ["file1.vhdx", "file2.vmdk", "file3.msi", "file4.hta", "file5.txt"]),
        (["file1.chm", "file2.cpl", "file3.scr", "file4.txt"],
         ["file1.chm", "file2.cpl", "file3.scr", "file4.txt"]),
        
        # executable extensions (priority 1)
        (["file1.txt", "file2.exe", "file3.dll", "file4.com", "file5.pdf"],
         ["file2.exe", "file3.dll", "file4.com", "file5.pdf", "file1.txt"]),
        (["file1.bat", "file2.cmd", "file3.jar", "file4.ps1", "file5.txt"],
         ["file1.bat", "file2.cmd", "file3.jar", "file4.ps1", "file5.txt"]),
        (["file1.sys", "file2.drv", "file3.txt"],
         ["file1.sys", "file2.drv", "file3.txt"]),
        
        # script extensions (priority 2)
        (["file1.txt", "file2.js", "file3.jse", "file4.vbs", "file5.pdf"],
         ["file2.js", "file3.jse", "file4.vbs", "file5.pdf", "file1.txt"]),
        (["file1.vbe", "file2.wsf", "file3.wsh", "file4.psm1", "file5.txt"],
         ["file1.vbe", "file2.wsf", "file3.wsh", "file4.psm1", "file5.txt"]),
        (["file1.sh", "file2.py", "file3.rb", "file4.pl", "file5.txt"],
         ["file1.sh", "file2.py", "file3.rb", "file4.pl", "file5.txt"]),
        (["file1.php", "file2.asp", "file3.aspx", "file4.txt"],
         ["file1.php", "file2.asp", "file3.aspx", "file4.txt"]),
        
        # office/pdf extensions (priority 3)
        (["file1.txt", "file2.doc", "file3.docx", "file4.xls", "file5.log"],
         ["file2.doc", "file3.docx", "file4.xls", "file1.txt", "file5.log"]),
        (["file1.xlsx", "file2.ppt", "file3.pptx", "file4.rtf", "file5.txt"],
         ["file1.xlsx", "file2.ppt", "file3.pptx", "file4.rtf", "file5.txt"]),
        (["file1.odt", "file2.ods", "file3.odp", "file4.pdf", "file5.txt"],
         ["file1.odt", "file2.ods", "file3.odp", "file4.pdf", "file5.txt"]),
        (["file1.mht", "file2.mhtml", "file3.xml", "file4.txt"],
         ["file1.mht", "file2.mhtml", "file3.xml", "file4.txt"]),
        
        # other extensions (priority 4) - lowest priority
        (["file1.txt", "file2.log", "file3.dat", "file4.tmp"],
         ["file1.txt", "file2.log", "file3.dat", "file4.tmp"]),
        
        # mixed priorities - testing sorting behavior
        (["file1.txt", "file2.exe", "file3.lnk", "file4.js", "file5.pdf"],
         ["file3.lnk", "file2.exe", "file4.js", "file5.pdf", "file1.txt"]),
        (["file1.pdf", "file2.scr", "file3.vbs", "file4.dll", "file5.doc"],
         ["file2.scr", "file4.dll", "file3.vbs", "file1.pdf", "file5.doc"]),
        
        # case insensitive handling
        (["file1.TXT", "file2.EXE", "file3.LNK", "file4.JS"],
         ["file3.LNK", "file2.EXE", "file4.JS", "file1.TXT"]),
        (["FILE1.PDF", "FILE2.SCR", "FILE3.VBS"],
         ["FILE2.SCR", "FILE3.VBS", "FILE1.PDF"]),
        
        # preserve order within same priority
        (["file1.txt", "file2.log", "file3.dat"],
         ["file1.txt", "file2.log", "file3.dat"]),
        (["file1.exe", "file2.dll", "file3.com"],
         ["file1.exe", "file2.dll", "file3.com"]),
        
        # complex mixed scenario
        (["readme.txt", "setup.exe", "malware.lnk", "script.js", "doc.pdf", 
          "data.log", "virus.scr", "code.py", "info.xml"],
         ["malware.lnk", "virus.scr", "setup.exe", "script.js", "code.py", "doc.pdf", "info.xml", "readme.txt", "data.log"]),
        
        # all same priority
        (["file1.exe", "file2.dll", "file3.com", "file4.bat", "file5.jar"],
         ["file1.exe", "file2.dll", "file3.com", "file4.bat", "file5.jar"]),
    ])
    def test_order_archive_file_list(self, file_list, expected):
        result = order_archive_file_list(file_list)
        assert result == expected
    
    @pytest.mark.unit
    def test_order_archive_file_list_preserves_order_within_priority(self):
        # test that files with same priority maintain their original order
        file_list = ["first.txt", "second.log", "third.dat", "fourth.tmp"]
        result = order_archive_file_list(file_list)
        assert result == ["first.txt", "second.log", "third.dat", "fourth.tmp"]
    
    @pytest.mark.unit
    def test_order_archive_file_list_all_extensions_covered(self):
        # test that all extension categories are properly handled
        file_list = [
            "attack.lnk",     # priority 0
            "exec.exe",       # priority 1  
            "script.js",      # priority 2
            "office.doc",     # priority 3
            "other.txt"       # priority 4
        ]
        result = order_archive_file_list(file_list)
        assert result == ["attack.lnk", "exec.exe", "script.js", "office.doc", "other.txt"]
    
    @pytest.mark.unit
    def test_order_archive_file_list_duplicate_extensions(self):
        # test files with same extensions maintain order
        file_list = ["first.exe", "second.exe", "third.exe", "fourth.txt"]
        result = order_archive_file_list(file_list)
        assert result == ["first.exe", "second.exe", "third.exe", "fourth.txt"]
    
    @pytest.mark.unit
    def test_order_archive_file_list_msi_in_both_categories(self):
        # .msi appears in both attack_exts and executable_exts
        # it should be treated as attack_exts (priority 0) since that's checked first
        file_list = ["file1.msi", "file2.exe", "file3.txt"]
        result = order_archive_file_list(file_list)
        assert result == ["file1.msi", "file2.exe", "file3.txt"]
        
        # verify msi gets priority 0 treatment
        file_list = ["file1.exe", "file2.msi", "file3.txt"]
        result = order_archive_file_list(file_list)
        assert result == ["file2.msi", "file1.exe", "file3.txt"]  # msi should come before exe
    
    @pytest.mark.unit 
    def test_order_archive_file_list_ps1_in_both_categories(self):
        # .ps1 appears in both executable_exts and script_exts
        # it should be treated as executable_exts (priority 1) since that's checked first
        file_list = ["file1.ps1", "file2.js", "file3.txt"]
        result = order_archive_file_list(file_list)
        assert result == ["file1.ps1", "file2.js", "file3.txt"]
        
        # verify ps1 gets priority 1 treatment
        file_list = ["file1.js", "file2.ps1", "file3.txt"]
        result = order_archive_file_list(file_list)
        assert result == ["file2.ps1", "file1.js", "file3.txt"]  # ps1 should come before js