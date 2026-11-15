import logging
import os

import pytest
from pydantic import BaseModel, ConfigDict, Field

from saq.configuration.config import get_config
from saq.environment import get_base_dir
from saq.filesystem.notification import FileWatcher


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    names: list[str] = Field(default_factory=list)
    limit: int = Field(default=5, ge=1)


@pytest.fixture
def check_every_time(monkeypatch):
    monkeypatch.setattr(get_config().global_settings, "check_watched_files_frequency", 0)


def _edit(path, text: str, mtime: int):
    path.write_text(text)
    # the watcher notices a change by its mtime, which can be unchanged within one tick
    os.utime(path, (mtime, mtime))


def _errors(caplog, text: str) -> list[logging.LogRecord]:
    return [r for r in caplog.records if r.levelno == logging.ERROR and text in r.getMessage()]


@pytest.mark.unit
def test_watch_settings_reads_nothing_until_first_use(tmp_path):
    path = tmp_path / "settings.yaml"
    watcher = FileWatcher()
    settings = watcher.watch_settings(str(path), Settings)

    # written after the holder was made, and still what the first use sees
    path.write_text("limit: 7\n")
    assert watcher.get_watched_files() == {}

    assert settings.value.limit == 7
    assert list(watcher.get_watched_files()) == [str(path)]


@pytest.mark.unit
def test_watch_settings_relative_path_is_under_saq_home():
    settings = FileWatcher().watch_settings("etc/settings.yaml", Settings)
    assert settings.path == os.path.join(get_base_dir(), "etc/settings.yaml")


@pytest.mark.unit
@pytest.mark.parametrize("text", ["", "# every key commented out\n"])
def test_watch_settings_empty_file_is_the_defaults(tmp_path, text):
    path = tmp_path / "settings.yaml"
    path.write_text(text)

    assert FileWatcher().watch_settings(str(path), Settings).value == Settings()


@pytest.mark.unit
def test_watch_settings_blank_path_is_the_defaults_and_watches_nothing():
    watcher = FileWatcher()

    assert watcher.watch_settings("", Settings).value == Settings()
    assert watcher.get_watched_files() == {}


@pytest.mark.unit
def test_watch_settings_reloads_and_keeps_the_last_good_value(tmp_path, check_every_time, caplog):
    path = tmp_path / "settings.yaml"
    path.write_text("names: [a]\n")
    watcher = FileWatcher()
    settings = watcher.watch_settings(str(path), Settings)
    assert settings.value.names == ["a"]

    for mtime, bad in enumerate(["names: [\n", "limit: 0\n", "nmes: [b]\n"], start=1):
        _edit(path, bad, mtime * 1_000_000)
        watcher.check_watched_files()
        assert settings.value.names == ["a"], bad

    records = _errors(caplog, f"unable to load settings file {path}")
    assert len(records) == 3
    # the traceback is what gets the record an error report
    assert all(r.exc_info and r.path == str(path) for r in records)

    with caplog.at_level(logging.INFO):
        _edit(path, "names: [b]\n", 4_000_000)
        watcher.check_watched_files()
    assert settings.value.names == ["b"]
    assert f"loaded settings file {path}" in caplog.text


@pytest.mark.unit
def test_watch_settings_missing_file_is_the_defaults(tmp_path, check_every_time, caplog):
    path = tmp_path / "settings.yaml"
    watcher = FileWatcher()
    settings = watcher.watch_settings(str(path), Settings)

    assert settings.value == Settings()
    [record] = _errors(caplog, f"watched file {path} does not exist")
    assert record.exc_info and record.path == str(path)

    path.write_text("limit: 9\n")
    watcher.check_watched_files()
    assert settings.value.limit == 9


@pytest.mark.unit
def test_watcher_reports_a_missing_file_once_per_disappearance(tmp_path, check_every_time, caplog):
    path = tmp_path / "watched"
    path.write_text("one")
    calls = []
    watcher = FileWatcher()
    watcher.watch_file(str(path), lambda: calls.append(path.read_text()))
    assert calls == ["one"]

    path.unlink()
    for _ in range(3):
        watcher.check_watched_files()
    assert len(_errors(caplog, "does not exist")) == 1

    _edit(path, "two", 1_000_000)
    watcher.check_watched_files()
    assert calls == ["one", "two"]
    assert len(_errors(caplog, "does not exist")) == 1

    path.unlink()
    watcher.check_watched_files()
    assert len(_errors(caplog, "does not exist")) == 2


@pytest.mark.unit
def test_watcher_reloads_a_file_put_back_with_its_old_mtime(tmp_path, check_every_time):
    path = tmp_path / "watched"
    _edit(path, "one", 1_000_000)
    calls = []
    watcher = FileWatcher()
    watcher.watch_file(str(path), lambda: calls.append(path.read_text()))
    assert calls == ["one"]

    path.unlink()
    watcher.check_watched_files()

    # restored from a backup that kept the mtime of the copy that was removed
    _edit(path, "two", 1_000_000)
    watcher.check_watched_files()
    assert calls == ["one", "two"]
