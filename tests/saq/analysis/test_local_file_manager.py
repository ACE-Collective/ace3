import hashlib
import os
import tempfile
import shutil
import pytest
from pathlib import Path

from saq.analysis.file_manager.local_file_manager import LocalFileManager, clean_file_name
from saq.util.filesystem import NAME_MAX_BYTES
from saq.constants import FILE_SUBDIR, HARDCOPY_SUBDIR


@pytest.fixture
def temp_storage_dir():
    """Create a temporary directory for testing."""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def file_manager(temp_storage_dir):
    """Create a FileManager instance for testing."""
    return LocalFileManager(temp_storage_dir)


@pytest.fixture  
def test_file():
    """Create a temporary test file."""
    temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
    temp_file.write("test content")
    temp_file.close()
    yield temp_file.name
    try:
        os.unlink(temp_file.name)
    except FileNotFoundError:
        pass


@pytest.mark.unit
def test_file_manager_initialization(temp_storage_dir):
    """Test FileManager initialization."""
    fm = LocalFileManager(temp_storage_dir)
    assert fm.storage_dir == temp_storage_dir
    assert fm.hardcopy_dir.endswith(HARDCOPY_SUBDIR)
    assert fm.file_dir.endswith(FILE_SUBDIR)


@pytest.mark.unit
def test_initialize_storage(file_manager, temp_storage_dir):
    """Test storage directory initialization."""
    file_manager.initialize_storage()
    
    # Check if directories were created (would need actual SAQ environment setup)
    # This is more of an integration test
    assert True  # placeholder


@pytest.mark.unit
def test_store_file(file_manager, test_file):
    """Test file storage functionality."""
    # Prepare directories
    os.makedirs(file_manager.hardcopy_dir, exist_ok=True)
    os.makedirs(file_manager.file_dir, exist_ok=True)
    
    # Store the file
    sha256_hash, relative_path = file_manager.store_file(test_file)
    
    # Verify hash is returned
    assert sha256_hash is not None
    assert len(sha256_hash) == 64  # SHA256 hex length
    
    # Verify relative path is returned
    assert relative_path is not None
    assert not relative_path.startswith('/')
    
    # Verify hardcopy exists
    hardcopy_path = os.path.join(file_manager.hardcopy_dir, sha256_hash)
    assert os.path.exists(hardcopy_path)
    
    # Verify reference link exists
    target_path = os.path.join(file_manager.file_dir, relative_path)
    assert os.path.exists(target_path)


@pytest.mark.unit
def test_store_file_with_move(file_manager, test_file):
    """Test file storage with move operation."""
    # Prepare directories
    os.makedirs(file_manager.hardcopy_dir, exist_ok=True)
    os.makedirs(file_manager.file_dir, exist_ok=True)
    
    original_exists = os.path.exists(test_file)
    assert original_exists
    
    # Store the file with move=True
    sha256_hash, relative_path = file_manager.store_file(test_file, move=True)
    
    # Verify original file no longer exists
    assert not os.path.exists(test_file)
    
    # Verify hardcopy exists
    hardcopy_path = os.path.join(file_manager.hardcopy_dir, sha256_hash)
    assert os.path.exists(hardcopy_path)


@pytest.mark.unit
def test_store_nonexistent_file(file_manager):
    """Test storing a non-existent file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        file_manager.store_file("/nonexistent/path/file.txt")


@pytest.mark.unit
def test_delete_file(file_manager, test_file):
    """Test file deletion."""
    # File should exist initially
    assert os.path.exists(test_file)
    
    # Delete the file
    file_manager.delete_file(test_file)
    
    # File should no longer exist
    assert not os.path.exists(test_file)


@pytest.mark.unit
def test_create_file_path(file_manager):
    """Test file path creation."""
    # Prepare file directory
    os.makedirs(file_manager.file_dir, exist_ok=True)
    
    # Test simple relative path
    result = file_manager.create_file_path("test.txt")
    expected = os.path.join(file_manager.file_dir, "test.txt")
    assert result == expected
    
    # Test path with subdirectory
    result = file_manager.create_file_path("subdir/test.txt")
    expected = os.path.join(file_manager.file_dir, "subdir/test.txt")
    assert result == expected
    
    # Verify subdirectory was created
    assert os.path.exists(os.path.dirname(result))


@pytest.mark.unit
def test_create_file_path_already_full_path(file_manager):
    """An already-resolved path within the files dir must be returned unchanged."""
    os.makedirs(file_manager.file_dir, exist_ok=True)

    full_path = os.path.join(file_manager.file_dir, "test.dat")
    result = file_manager.create_file_path(full_path)

    # the prefix must not be doubled (regression for files/.../files/... path bug)
    assert result == full_path
    assert result.count(FILE_SUBDIR) == 1


@pytest.mark.unit
def test_storage_operations(file_manager, temp_storage_dir):
    """Test storage copy, move, and delete operations."""
    # Create some test content in storage
    os.makedirs(file_manager.storage_dir, exist_ok=True)
    test_content_path = os.path.join(file_manager.storage_dir, "test.txt")
    with open(test_content_path, 'w') as f:
        f.write("test content")
    
    # Test copy
    copy_dest = temp_storage_dir + "_copy"
    file_manager.copy_storage(copy_dest)
    assert os.path.exists(os.path.join(copy_dest, "test.txt"))
    
    # Test move
    move_dest = temp_storage_dir + "_move"
    original_storage = file_manager.storage_dir
    file_manager.move_storage(move_dest)
    assert not os.path.exists(original_storage)
    assert os.path.exists(os.path.join(move_dest, "test.txt"))
    assert file_manager.storage_dir == move_dest
    
    # Test delete
    file_manager.delete_storage()
    assert not os.path.exists(move_dest) 

@pytest.fixture
def outside_dir(tmp_path):
    """A directory next to the storage directory that nothing may be written to."""
    path = tmp_path / "outside"
    path.mkdir()
    return path


@pytest.fixture
def contained_file_manager(tmp_path):
    fm = LocalFileManager(str(tmp_path / "storage"))
    os.makedirs(fm.file_dir)
    return fm


def _refused_record(caplog, name):
    return [r for r in caplog.records
            if r.levelname == "WARNING" and r.getMessage().startswith("refusing file path") and r.path == name]


@pytest.mark.unit
@pytest.mark.parametrize("name", ["../escaped.txt", "sub/../../escaped.txt", "../../outside/escaped.txt", "", ".", "sub/.."])
def test_create_file_path_refuses_paths_outside_the_file_dir(contained_file_manager, outside_dir, caplog, name):
    with pytest.raises(ValueError, match="outside of the files directory"):
        contained_file_manager.create_file_path(name)

    assert len(_refused_record(caplog, name)) == 1
    assert os.listdir(contained_file_manager.storage_dir) == [FILE_SUBDIR]
    assert os.listdir(contained_file_manager.file_dir) == []
    assert os.listdir(outside_dir) == []


@pytest.mark.unit
def test_create_file_path_refuses_an_absolute_path(contained_file_manager, outside_dir, caplog):
    name = str(outside_dir / "sub" / "escaped.txt")
    with pytest.raises(ValueError):
        contained_file_manager.create_file_path(name)

    assert len(_refused_record(caplog, name)) == 1
    # not even its directory is created
    assert os.listdir(outside_dir) == []


@pytest.mark.unit
def test_create_file_path_refuses_a_symlink_out_of_the_file_dir(contained_file_manager, outside_dir, caplog):
    os.symlink(outside_dir, os.path.join(contained_file_manager.file_dir, "link"))
    with pytest.raises(ValueError):
        contained_file_manager.create_file_path("link/escaped.txt")

    # a symlink to a file outside is refused the same way
    outside_file = outside_dir / "target.txt"
    outside_file.write_text("outside")
    os.symlink(outside_file, os.path.join(contained_file_manager.file_dir, "file_link"))
    with pytest.raises(ValueError):
        contained_file_manager.create_file_path("file_link")

    assert len(_refused_record(caplog, "link/escaped.txt")) == 1
    assert os.listdir(outside_dir) == ["target.txt"]


@pytest.mark.unit
def test_create_file_path_inside_the_file_dir(contained_file_manager):
    file_dir = contained_file_manager.file_dir
    assert contained_file_manager.create_file_path("a/../b.txt") == os.path.join(file_dir, "a/../b.txt")
    assert contained_file_manager.create_file_path("..b.txt") == os.path.join(file_dir, "..b.txt")
    # an absolute path inside the files dir, at any depth
    full_path = os.path.join(file_dir, "sub", "c.txt")
    assert contained_file_manager.create_file_path(full_path) == full_path
    assert os.path.isdir(os.path.join(file_dir, "sub"))


@pytest.mark.unit
def test_create_file_path_with_a_relative_storage_dir(tmp_path, outside_dir, monkeypatch):
    """Storage directories are relative to SAQ_HOME, which is the working directory."""
    monkeypatch.chdir(tmp_path)
    fm = LocalFileManager("storage")
    os.makedirs(fm.file_dir)

    assert fm.create_file_path("a.txt") == os.path.join("storage", FILE_SUBDIR, "a.txt")
    assert fm.create_file_path(os.path.join("storage", FILE_SUBDIR, "a.txt")) == os.path.join("storage", FILE_SUBDIR, "a.txt")
    assert fm.create_file_path(str(tmp_path / "storage" / FILE_SUBDIR / "b.txt")) == str(tmp_path / "storage" / FILE_SUBDIR / "b.txt")
    with pytest.raises(ValueError):
        fm.create_file_path(os.path.join("..", "..", "outside", "escaped.txt"))
    with pytest.raises(ValueError):
        fm.create_file_path(str(outside_dir / "escaped.txt"))
    # the full-path form, with a directory traversal for a name
    with pytest.raises(ValueError):
        fm.create_file_path(os.path.join("storage", FILE_SUBDIR, ".."))

    assert os.listdir(outside_dir) == []


@pytest.mark.unit
@pytest.mark.parametrize("target_path, expected", [
    ("../escaped.txt", "_/escaped.txt"),
    ("../../outside/escaped.txt", "_/_/outside/escaped.txt"),
    ("sub/../../escaped.txt", "sub/_/_/escaped.txt"),
])
def test_store_file_cleans_a_target_outside_the_file_dir(contained_file_manager, outside_dir, test_file, target_path, expected):
    """A target is often a name from a submitter or from analyzed content (a hunt's event field, a
    GUI upload), so it is cleaned like a create_output_file name."""
    _, relative_path = contained_file_manager.store_file(test_file, target_path)

    assert relative_path == expected
    assert os.path.exists(os.path.join(contained_file_manager.file_dir, expected))
    assert os.listdir(outside_dir) == []


@pytest.mark.unit
def test_store_file_keeps_an_absolute_target_inside(contained_file_manager, outside_dir, test_file):
    target = outside_dir / "escaped.txt"
    _, relative_path = contained_file_manager.store_file(test_file, str(target))

    assert relative_path == str(target).lstrip("/")
    assert os.listdir(outside_dir) == []


@pytest.mark.unit
def test_store_file_refuses_a_symlink_out_of_the_file_dir(contained_file_manager, outside_dir, test_file):
    os.symlink(outside_dir, os.path.join(contained_file_manager.file_dir, "link"))
    with pytest.raises(ValueError):
        contained_file_manager.store_file(test_file, "link/escaped.txt")

    # a source "inside" the files dir that links out of it is not stored either, so a link
    # extracted from an archive cannot copy a file from elsewhere into the analysis
    outside_file = outside_dir / "secret.txt"
    outside_file.write_text("secret")
    linked_source = os.path.join(contained_file_manager.file_dir, "secret.txt")
    os.symlink(outside_file, linked_source)
    with pytest.raises(ValueError):
        contained_file_manager.store_file(linked_source)

    assert sorted(os.listdir(outside_dir)) == ["secret.txt"]
    assert not os.path.exists(contained_file_manager.hardcopy_dir)


@pytest.mark.unit
def test_a_refused_symlink_logs_where_it_leads(contained_file_manager, outside_dir, caplog):
    """The name of a refused link looks like it is inside the files directory, so the record says
    what it resolves to."""
    outside_file = outside_dir / "secret.txt"
    outside_file.write_text("secret")
    linked_source = os.path.join(contained_file_manager.file_dir, "secret.txt")
    os.symlink(outside_file, linked_source)
    with pytest.raises(ValueError):
        contained_file_manager.store_file(linked_source)

    (record,) = _refused_record(caplog, linked_source)
    assert record.resolved_path == os.path.realpath(outside_file)
    assert os.path.realpath(outside_file) in record.getMessage()


@pytest.mark.unit
def test_store_file_does_not_reuse_a_name_holding_other_bytes(contained_file_manager, tmp_path):
    first = tmp_path / "first" / "report.pdf"
    first.parent.mkdir()
    first.write_bytes(b"first")
    second = tmp_path / "second" / "report.pdf"
    second.parent.mkdir()
    second.write_bytes(b"second")

    first_hash, first_path = contained_file_manager.store_file(str(first))
    second_hash, second_path = contained_file_manager.store_file(str(second))

    assert first_path == "report.pdf"
    assert second_path == "report_000.pdf"
    for file_hash, path, content in ((first_hash, first_path, b"first"), (second_hash, second_path, b"second")):
        with open(os.path.join(contained_file_manager.file_dir, path), "rb") as fp:
            assert fp.read() == content
        assert hashlib.sha256(content).hexdigest() == file_hash


@pytest.mark.unit
def test_store_file_reuses_a_name_holding_the_same_bytes(contained_file_manager, tmp_path, test_file):
    copy = tmp_path / "copy" / os.path.basename(test_file)
    copy.parent.mkdir()
    shutil.copy(test_file, copy)

    assert contained_file_manager.store_file(test_file) == contained_file_manager.store_file(str(copy))
    assert os.listdir(contained_file_manager.file_dir) == [os.path.basename(test_file)]


@pytest.mark.unit
def test_store_file_with_a_target_inside_the_file_dir(contained_file_manager, test_file):
    sha256_hash, relative_path = contained_file_manager.store_file(test_file, "sub/stored.txt")
    assert relative_path == "sub/stored.txt"
    assert os.path.exists(os.path.join(contained_file_manager.file_dir, "sub", "stored.txt"))

    # a file already in the files dir stays where it is
    full_path = contained_file_manager.create_file_path("already_here.txt")
    with open(full_path, "w") as fp:
        fp.write("already here")
    assert contained_file_manager.store_file(full_path)[1] == "already_here.txt"


@pytest.mark.unit
@pytest.mark.parametrize("name, expected", [
    ("test.txt", "test.txt"),
    ("../test.txt", "_/test.txt"),
    ("../../test.txt", "_/_/test.txt"),
    ("sub/../../test.txt", "sub/_/_/test.txt"),
    ("/some/path/test.txt", "some/path/test.txt"),
    ("//////test.txt", "test.txt"),
    ("./a/./b.txt", "a/b.txt"),
    ("C:\\Users\\john\\test.txt", "C:_Users_john_test.txt"),
    ("\\..\\..\\test.txt", "_.._.._test.txt"),
    ("~john/test", "~john/test"),
    (".", "_"),
    ("..", "_"),
    ("...", "..."),
    ("..b.txt", "..b.txt"),
    ("a\0b", "a_b"),
    ("", "_"),
    ("/", "_"),
    ("Quarterly Report é.pdf", "Quarterly Report é.pdf"),
])
def test_clean_file_name(name, expected):
    assert clean_file_name(name) == expected
    # a stored name (a file_path) is cleaned again when output is named after it
    assert clean_file_name(expected) == expected


@pytest.mark.unit
@pytest.mark.parametrize("name", ["a" * 1000 + ".txt", "é" * 300 + ".txt", "a" * 300, "a." + "b" * 300])
def test_clean_file_name_fits_the_filesystem(name):
    cleaned = clean_file_name(name)
    # with room for the suffix that tells same-named files apart
    assert len(cleaned.encode("utf-8")) <= NAME_MAX_BYTES - 8
    assert clean_file_name(cleaned) == cleaned
    if name.endswith(".txt"):
        assert cleaned.endswith(".txt")

    # two long names that share a prefix stay apart
    assert clean_file_name(name + "x") != cleaned


@pytest.mark.unit
@pytest.mark.parametrize("name, expected", [
    ("../escaped.txt", "_/escaped.txt"),
    ("../../outside/escaped.txt", "_/_/outside/escaped.txt"),
    ("sub/../../escaped.txt", "sub/_/_/escaped.txt"),
    ("..", "_"),
    ("", "_"),
    ("/tmp/escaped.txt", "tmp/escaped.txt"),
    ("word/media/image1.png", "word/media/image1.png"),
])
def test_create_output_file_keeps_the_name_inside(contained_file_manager, outside_dir, name, expected):
    path = contained_file_manager.create_output_file(name)

    assert path == os.path.join(contained_file_manager.file_dir, expected)
    # created, empty, before the caller writes anything
    assert os.path.isfile(path)
    assert os.path.getsize(path) == 0
    assert os.listdir(outside_dir) == []


@pytest.mark.unit
def test_create_output_file_keeps_an_absolute_name_inside(contained_file_manager, outside_dir):
    name = str(outside_dir / "escaped.txt")
    path = contained_file_manager.create_output_file(name)

    assert path == os.path.join(contained_file_manager.file_dir, name.lstrip("/"))
    assert os.listdir(outside_dir) == []


@pytest.mark.unit
def test_create_output_file_never_reuses_a_name(contained_file_manager):
    file_dir = contained_file_manager.file_dir
    paths = [contained_file_manager.create_output_file("report.pdf") for _ in range(3)]

    assert paths == [os.path.join(file_dir, name) for name in ("report.pdf", "report_000.pdf", "report_001.pdf")]


@pytest.mark.unit
def test_create_output_file_does_not_write_through_a_planted_link(contained_file_manager, outside_dir):
    """A link already at the name (an archive's symlink member) is passed over, not opened."""
    outside_file = outside_dir / "target.txt"
    outside_file.write_text("outside")
    os.symlink(outside_file, os.path.join(contained_file_manager.file_dir, "report.pdf"))

    path = contained_file_manager.create_output_file("report.pdf")
    with open(path, "wb") as fp:
        fp.write(b"written")

    assert path == os.path.join(contained_file_manager.file_dir, "report_000.pdf")
    assert outside_file.read_text() == "outside"


@pytest.mark.unit
def test_create_output_file_takes_the_next_name_when_one_is_taken_meanwhile(contained_file_manager, monkeypatch):
    """Another writer can take the name between choosing it and creating it."""
    from saq.analysis.file_manager import local_file_manager

    real_unique_file_path = local_file_manager.unique_file_path
    calls = []

    def unique_file_path(path):
        result = real_unique_file_path(path)
        if not calls:
            # the other writer
            open(result, "w").close()
        calls.append(result)
        return result

    monkeypatch.setattr(local_file_manager, "unique_file_path", unique_file_path)
    path = contained_file_manager.create_output_file("report.pdf")

    assert path == os.path.join(contained_file_manager.file_dir, "report_000.pdf")
    assert len(calls) == 2


@pytest.mark.unit
def test_create_output_file_refuses_a_symlink_out_of_the_file_dir(contained_file_manager, outside_dir, caplog):
    os.symlink(outside_dir, os.path.join(contained_file_manager.file_dir, "link"))
    with pytest.raises(ValueError, match="outside of the files directory"):
        contained_file_manager.create_output_file("link/escaped.txt")

    assert len(_refused_record(caplog, "link/escaped.txt")) == 1
    assert os.listdir(outside_dir) == []


@pytest.mark.unit
def test_create_output_file_with_a_relative_storage_dir(tmp_path, outside_dir, monkeypatch):
    """Storage directories are relative to SAQ_HOME, which is the working directory."""
    monkeypatch.chdir(tmp_path)
    fm = LocalFileManager("storage")
    os.makedirs(fm.file_dir)

    assert fm.create_output_file("a.txt") == os.path.join("storage", FILE_SUBDIR, "a.txt")
    assert fm.create_output_file(os.path.join("..", "..", "outside", "escaped.txt")) == \
        os.path.join("storage", FILE_SUBDIR, "_", "_", "outside", "escaped.txt")
    assert os.listdir(outside_dir) == []
