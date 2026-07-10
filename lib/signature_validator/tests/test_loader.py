import os
import stat
import subprocess
import sys
import textwrap

import pytest

from hunt_compiler import CompiledHunt, EmbeddedFile, compile_hunt, load_compiled_hunt
from hunt_compiler.compiler import PKG_TOKEN


def _by_kind(compiled, kind):
    return [a for a in compiled.assets if a.kind == kind]


class TestLoadCompiledHunt:
    def test_writes_yaml_files(self, simple_hunt, tmp_path):
        compiled = compile_hunt(str(simple_hunt))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        target_path = load_compiled_hunt(compiled, str(target_dir))

        assert os.path.isfile(target_path)
        assert target_path == str(target_dir / "hunts" / "test" / "test.yaml")

        with open(target_path) as f:
            content = f.read()
        assert "simple_test" in content

    def test_writes_query_files(self, simple_hunt, tmp_path):
        compiled = compile_hunt(str(simple_hunt))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        load_compiled_hunt(compiled, str(target_dir))

        query_path = target_dir / "hunts" / "test" / "test.query"
        assert query_path.is_file()
        assert "index=proxy" in query_path.read_text()

    def test_writes_include_files(self, hunt_with_includes, tmp_path):
        compiled = compile_hunt(str(hunt_with_includes))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        load_compiled_hunt(compiled, str(target_dir))

        defaults_path = target_dir / "hunts" / "includes" / "defaults.include.yaml"
        assert defaults_path.is_file()
        assert "default_tag" in defaults_path.read_text()

    def test_writes_query_inline_includes(self, hunt_with_query_includes, tmp_path):
        compiled = compile_hunt(str(hunt_with_query_includes))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        load_compiled_hunt(compiled, str(target_dir))

        ips_path = target_dir / "hunts" / "test" / "ips.txt"
        assert ips_path.is_file()
        assert "1.1.1.1" in ips_path.read_text()

    def test_writes_executables_with_permissions(self, hunt_with_inline_executable, tmp_path):
        compiled = compile_hunt(str(hunt_with_inline_executable))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        load_compiled_hunt(compiled, str(target_dir))

        script_path = target_dir / "hunts" / "scripts" / "enrich.py"
        assert script_path.is_file()
        assert "#!/usr/bin/env python3" in script_path.read_text()

        file_mode = stat.S_IMODE(os.stat(script_path).st_mode)
        assert file_mode == 0o700

    def test_expands_pkg_token_in_yaml(self, hunt_with_inline_executable, tmp_path):
        compiled = compile_hunt(str(hunt_with_inline_executable))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        target_path = load_compiled_hunt(compiled, str(target_dir))

        with open(target_path) as f:
            yaml_content = f.read()

        expected_abs_path = str(target_dir / "hunts" / "scripts" / "enrich.py")
        assert expected_abs_path in yaml_content
        assert PKG_TOKEN not in yaml_content

    def test_expands_pkg_token_in_commands_include(self, hunt_with_executables, tmp_path, hunt_dir):
        compiled = compile_hunt(str(hunt_with_executables))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        load_compiled_hunt(compiled, str(target_dir))

        commands_path = target_dir / "hunts" / "commands" / "test_commands.include.yaml"
        content = commands_path.read_text()

        original_abs_path = str(hunt_dir / "hunts" / "scripts" / "check_user.py")
        new_abs_path = str(target_dir / "hunts" / "scripts" / "check_user.py")

        assert original_abs_path not in content
        assert new_abs_path in content
        assert PKG_TOKEN not in content


class TestLoadSupportingFiles:
    def test_writes_supporting_files(self, hunt_with_supporting_files, tmp_path):
        compiled = compile_hunt(str(hunt_with_supporting_files))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        load_compiled_hunt(compiled, str(target_dir))

        data_path = target_dir / "hunts" / "scripts" / "ip_ranges.json"
        assert data_path.is_file()
        assert "10.0.0.0/8" in data_path.read_text()

    def test_supporting_file_accessible_from_script(self, hunt_with_supporting_files, exec_tmp_path):
        compiled = compile_hunt(str(hunt_with_supporting_files))
        target_dir = os.path.join(exec_tmp_path, "output")
        os.makedirs(target_dir)

        load_compiled_hunt(compiled, target_dir)

        script_path = os.path.join(target_dir, "hunts", "scripts", "check_ip.py")
        result = subprocess.run(
            [script_path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0
        assert "10.0.0.0/8" in result.stdout


class TestLoadBinaryExecutable:
    def test_writes_binary_executable(self, hunt_with_binary_executable, tmp_path):
        hunt_file, original_bytes = hunt_with_binary_executable
        compiled = compile_hunt(str(hunt_file))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        load_compiled_hunt(compiled, str(target_dir))

        binary_path = target_dir / "hunts" / "scripts" / "lookup"
        assert binary_path.is_file()
        assert binary_path.read_bytes() == original_bytes

        file_mode = stat.S_IMODE(os.stat(binary_path).st_mode)
        assert file_mode == 0o755


class TestRoundTrip:
    def test_compile_serialize_deserialize_load(self, simple_hunt, tmp_path):
        """Full round-trip: compile -> JSON -> deserialize -> load."""
        compiled = compile_hunt(str(simple_hunt))
        json_str = compiled.model_dump_json()

        restored = CompiledHunt.model_validate_json(json_str)

        target_dir = tmp_path / "output"
        target_dir.mkdir()
        target_path = load_compiled_hunt(restored, str(target_dir))

        assert os.path.isfile(target_path)
        query_path = target_dir / "hunts" / "test" / "test.query"
        assert query_path.is_file()

    def test_compile_serialize_deserialize_load_with_executables(
        self, hunt_with_executables, tmp_path
    ):
        """Round-trip with executable files preserves permissions."""
        compiled = compile_hunt(str(hunt_with_executables))
        json_str = compiled.model_dump_json()
        restored = CompiledHunt.model_validate_json(json_str)

        target_dir = tmp_path / "output"
        target_dir.mkdir()
        load_compiled_hunt(restored, str(target_dir))

        script_path = target_dir / "hunts" / "scripts" / "check_user.py"
        assert script_path.is_file()
        file_mode = stat.S_IMODE(os.stat(script_path).st_mode)
        assert file_mode == 0o755

    def test_compile_serialize_deserialize_load_binary_executable(
        self, hunt_with_binary_executable, tmp_path
    ):
        """Round-trip with binary executable preserves exact bytes and permissions."""
        hunt_file, original_bytes = hunt_with_binary_executable
        compiled = compile_hunt(str(hunt_file))
        json_str = compiled.model_dump_json()
        restored = CompiledHunt.model_validate_json(json_str)

        target_dir = tmp_path / "output"
        target_dir.mkdir()
        load_compiled_hunt(restored, str(target_dir))

        binary_path = target_dir / "hunts" / "scripts" / "lookup"
        assert binary_path.is_file()
        assert binary_path.read_bytes() == original_bytes
        file_mode = stat.S_IMODE(os.stat(binary_path).st_mode)
        assert file_mode == 0o755


class TestLoadRelativePaths:
    def test_rewrites_resolved_relative_predefined_paths(
        self, hunt_with_relative_executable_paths, tmp_path
    ):
        compiled = compile_hunt(str(hunt_with_relative_executable_paths))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        load_compiled_hunt(compiled, str(target_dir))

        commands_path = target_dir / "hunts" / "commands" / "test_commands.include.yaml"
        content = commands_path.read_text()

        new_abs_path = str(target_dir / "hunts" / "scripts" / "check_user.py")
        assert new_abs_path in content
        assert "../scripts/" not in content

    def test_rewrites_resolved_relative_supporting_files(
        self, hunt_with_relative_supporting_files, tmp_path
    ):
        compiled = compile_hunt(str(hunt_with_relative_supporting_files))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        load_compiled_hunt(compiled, str(target_dir))

        commands_path = target_dir / "hunts" / "commands" / "ip_commands.include.yaml"
        content = commands_path.read_text()

        assert str(target_dir / "hunts" / "scripts" / "check_ip.py") in content
        assert str(target_dir / "hunts" / "scripts" / "ip_ranges.json") in content
        assert "../scripts/" not in content

    def test_rewrites_resolved_relative_inline_executable(
        self, hunt_with_relative_inline_executable, tmp_path
    ):
        compiled = compile_hunt(str(hunt_with_relative_inline_executable))
        target_dir = tmp_path / "output"
        target_dir.mkdir()

        target_path = load_compiled_hunt(compiled, str(target_dir))

        with open(target_path) as f:
            yaml_content = f.read()

        new_abs_path = str(target_dir / "hunts" / "scripts" / "enrich.py")
        assert new_abs_path in yaml_content
        assert "../scripts/" not in yaml_content

    def test_round_trip_with_relative_paths(
        self, hunt_with_relative_executable_paths, tmp_path
    ):
        """Full round-trip: compile -> JSON -> deserialize -> load with relative paths."""
        compiled = compile_hunt(str(hunt_with_relative_executable_paths))
        json_str = compiled.model_dump_json()
        restored = CompiledHunt.model_validate_json(json_str)

        target_dir = tmp_path / "output"
        target_dir.mkdir()
        target_path = load_compiled_hunt(restored, str(target_dir))

        assert os.path.isfile(target_path)
        script_path = target_dir / "hunts" / "scripts" / "check_user.py"
        assert script_path.is_file()


class TestLoadCrossTreeHunt:
    """Regression coverage for the monorepo shape where a hunt in one tree
    references files in sibling trees. After compile, the loader must write
    every file inside temp_dir and expand __pkg__/ tokens without leaking the
    original filesystem locations.
    """

    def test_files_land_inside_temp_dir(self, hunt_with_cross_tree_references, tmp_path):
        compiled = compile_hunt(str(hunt_with_cross_tree_references))

        target_dir = tmp_path / "output"
        target_dir.mkdir()
        load_compiled_hunt(compiled, str(target_dir))

        script_path = target_dir / "hunts" / "scripts" / "is_service_account.py"
        commands_path = target_dir / "hunts" / "commands" / "azure_commands.include.yaml"
        hunt_target = target_dir / "hunts" / "splunk" / "azure_single_factor_authentication.yaml"

        assert script_path.is_file()
        assert commands_path.is_file()
        assert hunt_target.is_file()

        file_mode = stat.S_IMODE(os.stat(script_path).st_mode)
        assert file_mode == 0o755

    def test_yaml_paths_rewritten_to_temp_dir(self, hunt_with_cross_tree_references, tmp_path, hunt_dir):
        compiled = compile_hunt(str(hunt_with_cross_tree_references))

        target_dir = tmp_path / "output"
        target_dir.mkdir()
        load_compiled_hunt(compiled, str(target_dir))

        commands_content = (
            target_dir / "hunts" / "commands" / "azure_commands.include.yaml"
        ).read_text()

        rewritten_script = str(target_dir / "hunts" / "scripts" / "is_service_account.py")
        assert rewritten_script in commands_content

        original_script_path = str(hunt_dir / "hunts" / "scripts" / "is_service_account.py")
        assert original_script_path not in commands_content
        assert "../scripts/" not in commands_content
        assert PKG_TOKEN not in commands_content

    def test_round_trip_json_serialization(self, hunt_with_cross_tree_references, tmp_path):
        compiled = compile_hunt(str(hunt_with_cross_tree_references))

        json_str = compiled.model_dump_json()
        restored = CompiledHunt.model_validate_json(json_str)

        target_dir = tmp_path / "output"
        target_dir.mkdir()
        target_path = load_compiled_hunt(restored, str(target_dir))

        assert os.path.isfile(target_path)
        assert (target_dir / "hunts" / "scripts" / "is_service_account.py").is_file()


class TestLoadVersionGuard:
    def test_loader_rejects_unsupported_version(self, tmp_path):
        ch = CompiledHunt(
            version=99,
            target="test.yaml",
            package_root="/tmp",
            assets=[EmbeddedFile(kind="yaml", path="test.yaml", content="rule: {}")],
        )
        with pytest.raises(ValueError, match="unsupported CompiledHunt version"):
            load_compiled_hunt(ch, str(tmp_path))


class TestLoadNonAscii:
    """A hunt containing non-ascii characters must materialize regardless of locale."""

    ARROW = "→"

    def test_writes_non_ascii_yaml(self, tmp_path):
        content = f"rule:\n  description: source {self.ARROW} destination\n"
        ch = CompiledHunt(
            target="hunts/test/test.yaml",
            package_root="/tmp",
            assets=[EmbeddedFile(kind="yaml", path="hunts/test/test.yaml", content=content)],
        )

        target_path = load_compiled_hunt(ch, str(tmp_path))

        with open(target_path, encoding="utf-8") as f:
            assert f.read() == content

    def test_writes_non_ascii_query(self, tmp_path):
        content = f"index=proxy note=\"a {self.ARROW} b\"\n"
        ch = CompiledHunt(
            target="hunts/test/test.yaml",
            package_root="/tmp",
            assets=[
                EmbeddedFile(kind="yaml", path="hunts/test/test.yaml", content="rule: {}"),
                EmbeddedFile(kind="query", path="hunts/test/test.query", content=content),
            ],
        )

        load_compiled_hunt(ch, str(tmp_path))

        query_path = tmp_path / "hunts" / "test" / "test.query"
        with open(query_path, encoding="utf-8") as f:
            assert f.read() == content

    def test_loads_under_ascii_locale(self, tmp_path):
        """Regression: uwsgi embeds python with utf-8 mode off, so a C locale means
        the default open() encoding is ascii. The loader must not depend on it."""
        import hunt_compiler

        package_root = os.path.dirname(os.path.dirname(os.path.abspath(hunt_compiler.__file__)))
        script = textwrap.dedent(
            """
            import locale, sys
            assert locale.getpreferredencoding(False).lower() in ("ansi_x3.4-1968", "ascii"), (
                "expected an ascii locale, got %s" % locale.getpreferredencoding(False))
            assert sys.flags.utf8_mode == 0, "expected utf-8 mode off"

            from hunt_compiler import CompiledHunt, EmbeddedFile, load_compiled_hunt
            content = "rule:\\n  description: source \\u2192 destination\\n"
            ch = CompiledHunt(
                target="hunts/test/test.yaml",
                package_root="/tmp",
                assets=[EmbeddedFile(kind="yaml", path="hunts/test/test.yaml", content=content)],
            )
            target_path = load_compiled_hunt(ch, sys.argv[1])
            with open(target_path, encoding="utf-8") as f:
                written = f.read()
            assert written == content, ascii(written)
            print("OK")
            """
        )

        env = dict(os.environ)
        env.update(
            {
                "PYTHONPATH": package_root,
                "PYTHONUTF8": "0",
                "PYTHONCOERCECLOCALE": "0",
                "LC_ALL": "C",
                "LANG": "C",
            }
        )
        result = subprocess.run(
            [sys.executable, "-X", "utf8=0", "-c", script, str(tmp_path)],
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
        assert "OK" in result.stdout


class TestExecutableScripts:
    """Verify that loaded executable scripts can actually be executed."""

    def test_loaded_script_can_execute(self, hunt_with_executables, exec_tmp_path):
        compiled = compile_hunt(str(hunt_with_executables))
        target_dir = os.path.join(exec_tmp_path, "output")
        os.makedirs(target_dir)

        load_compiled_hunt(compiled, target_dir)

        script_path = os.path.join(target_dir, "hunts", "scripts", "check_user.py")
        result = subprocess.run(
            [script_path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0
        assert "true" in result.stdout

    def test_loaded_inline_script_can_execute(self, hunt_with_inline_executable, exec_tmp_path):
        compiled = compile_hunt(str(hunt_with_inline_executable))
        target_dir = os.path.join(exec_tmp_path, "output")
        os.makedirs(target_dir)

        load_compiled_hunt(compiled, target_dir)

        script_path = os.path.join(target_dir, "hunts", "scripts", "enrich.py")
        result = subprocess.run(
            [script_path],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0
