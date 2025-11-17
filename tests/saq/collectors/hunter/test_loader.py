import pytest
from pydantic import BaseModel, Field

from saq.collectors.hunter.loader import load_from_yaml, deep_merge


class SimpleConfig(BaseModel):
    """Simple config for testing basic functionality."""
    name: str = Field(..., description="The name")
    value: str = Field(..., description="The value")


@pytest.mark.unit
class TestDeepMerge:
    """Tests for the deep_merge function."""

    def test_merge_simple_values(self):
        """should replace simple values in base with values from override"""
        base = {"key1": "value1", "key2": "value2"}
        override = {"key2": "new_value2", "key3": "value3"}

        result = deep_merge(base, override)

        assert result == {"key1": "value1", "key2": "new_value2", "key3": "value3"}

    def test_merge_nested_dicts(self):
        """should recursively merge nested dictionaries"""
        base = {"outer": {"inner1": "value1", "inner2": "value2"}}
        override = {"outer": {"inner2": "new_value2", "inner3": "value3"}}

        result = deep_merge(base, override)

        assert result == {
            "outer": {"inner1": "value1", "inner2": "new_value2", "inner3": "value3"}
        }

    def test_merge_lists_avoiding_duplicates(self):
        """should extend lists avoiding duplicates"""
        base = {"tags": ["tag1", "tag2"]}
        override = {"tags": ["tag2", "tag3", "tag4"]}

        result = deep_merge(base, override)

        assert result == {"tags": ["tag1", "tag2", "tag3", "tag4"]}

    def test_merge_lists_preserves_order(self):
        """should preserve the order when merging lists"""
        base = {"items": [1, 2, 3]}
        override = {"items": [3, 4, 5]}

        result = deep_merge(base, override)

        assert result == {"items": [1, 2, 3, 4, 5]}

    def test_merge_empty_base(self):
        """should return override when base is empty"""
        base = {}
        override = {"key1": "value1", "key2": {"nested": "value"}}

        result = deep_merge(base, override)

        assert result == {"key1": "value1", "key2": {"nested": "value"}}

    def test_merge_empty_override(self):
        """should return base when override is empty"""
        base = {"key1": "value1", "key2": {"nested": "value"}}
        override = {}

        result = deep_merge(base, override)

        assert result == {"key1": "value1", "key2": {"nested": "value"}}

    def test_merge_deeply_nested_dicts(self):
        """should merge deeply nested dictionaries"""
        base = {"level1": {"level2": {"level3": {"value": "old"}}}}
        override = {"level1": {"level2": {"level3": {"value": "new", "extra": "data"}}}}

        result = deep_merge(base, override)

        assert result == {"level1": {"level2": {"level3": {"value": "new", "extra": "data"}}}}

    def test_merge_mixed_types_dict_override(self):
        """should replace when override changes type from non-dict to dict"""
        base = {"key": "simple_value"}
        override = {"key": {"nested": "value"}}

        result = deep_merge(base, override)

        assert result == {"key": {"nested": "value"}}

    def test_merge_mixed_types_simple_override(self):
        """should replace when override changes type from dict to simple value"""
        base = {"key": {"nested": "value"}}
        override = {"key": "simple_value"}

        result = deep_merge(base, override)

        assert result == {"key": "simple_value"}

    def test_merge_mixed_types_list_to_dict(self):
        """should replace when override changes type from list to dict"""
        base = {"key": ["item1", "item2"]}
        override = {"key": {"nested": "value"}}

        result = deep_merge(base, override)

        assert result == {"key": {"nested": "value"}}

    def test_merge_mixed_types_dict_to_list(self):
        """should replace when override changes type from dict to list"""
        base = {"key": {"nested": "value"}}
        override = {"key": ["item1", "item2"]}

        result = deep_merge(base, override)

        assert result == {"key": ["item1", "item2"]}

    def test_merge_does_not_modify_base(self):
        """should not modify the original base dictionary"""
        base = {"key1": "value1", "nested": {"inner": "value"}}
        base_copy = {"key1": "value1", "nested": {"inner": "value"}}
        override = {"key2": "value2", "nested": {"inner": "new_value"}}

        result = deep_merge(base, override)

        # base should remain unchanged
        assert base == base_copy
        # but result should have the merge
        assert result == {"key1": "value1", "key2": "value2", "nested": {"inner": "new_value"}}

    def test_merge_complex_scenario(self):
        """should handle complex merge with multiple data types"""
        base = {
            "name": "base_name",
            "tags": ["tag1", "tag2"],
            "config": {"setting1": "value1", "setting2": "value2"},
            "count": 5,
        }
        override = {
            "tags": ["tag2", "tag3"],
            "config": {"setting2": "new_value2", "setting3": "value3"},
            "count": 10,
            "new_field": "new_value",
        }

        result = deep_merge(base, override)

        assert result == {
            "name": "base_name",
            "tags": ["tag1", "tag2", "tag3"],
            "config": {"setting1": "value1", "setting2": "new_value2", "setting3": "value3"},
            "count": 10,
            "new_field": "new_value",
        }

    def test_merge_with_none_values(self):
        """should handle None values correctly"""
        base = {"key1": "value1", "key2": None}
        override = {"key2": "new_value", "key3": None}

        result = deep_merge(base, override)

        assert result == {"key1": "value1", "key2": "new_value", "key3": None}

    def test_merge_list_with_dict_items(self):
        """should handle lists containing dictionaries"""
        base = {"items": [{"id": 1, "name": "item1"}]}
        override = {"items": [{"id": 2, "name": "item2"}]}

        result = deep_merge(base, override)

        # lists are extended, not merged element-wise
        assert result == {"items": [{"id": 1, "name": "item1"}, {"id": 2, "name": "item2"}]}

    def test_merge_list_duplicate_detection(self):
        """should detect duplicates in lists correctly"""
        base = {"numbers": [1, 2, 3]}
        override = {"numbers": [2, 3, 4]}

        result = deep_merge(base, override)

        # 2 and 3 should not be duplicated
        assert result == {"numbers": [1, 2, 3, 4]}

    def test_merge_empty_nested_dict(self):
        """should handle empty nested dictionaries"""
        base = {"outer": {}}
        override = {"outer": {"inner": "value"}}

        result = deep_merge(base, override)

        assert result == {"outer": {"inner": "value"}}

    def test_merge_empty_list(self):
        """should handle empty lists"""
        base = {"items": []}
        override = {"items": ["item1", "item2"]}

        result = deep_merge(base, override)

        assert result == {"items": ["item1", "item2"]}

    def test_merge_multiple_levels_mixed_types(self):
        """should handle multiple levels with mixed types"""
        base = {
            "rule": {
                "name": "base_rule",
                "tags": ["tag1"],
                "config": {"enabled": True, "timeout": 30},
            }
        }
        override = {
            "rule": {
                "tags": ["tag2", "tag3"],
                "config": {"timeout": 60, "retries": 3},
                "description": "new description",
            }
        }

        result = deep_merge(base, override)

        assert result == {
            "rule": {
                "name": "base_rule",
                "tags": ["tag1", "tag2", "tag3"],
                "config": {"enabled": True, "timeout": 60, "retries": 3},
                "description": "new description",
            }
        }


@pytest.mark.unit
class TestYAMLLoaderBasicFunctionality:
    """Tests for basic YAML loading without includes."""

    def test_load_simple_yaml_file(self, tmpdir):
        """should load a simple YAML file without includes"""
        yaml_content = """rule:
  name: test_rule
  value: test_value
"""
        yaml_file = tmpdir / "simple.yaml"
        yaml_file.write(yaml_content)

        config, _ = load_from_yaml(str(yaml_file), SimpleConfig)

        assert config.name == "test_rule"
        assert config.value == "test_value"

    def test_load_nonexistent_file(self, tmpdir):
        """should raise exception when loading non-existent file"""
        with pytest.raises(Exception):
            load_from_yaml(str(tmpdir / "nonexistent.yaml"), SimpleConfig)

    def test_load_invalid_yaml(self, tmpdir):
        """should raise exception when loading invalid YAML"""
        yaml_content = """rule:
  name: test_rule
  value: [invalid yaml structure
"""
        yaml_file = tmpdir / "invalid.yaml"
        yaml_file.write(yaml_content)

        with pytest.raises(Exception):
            load_from_yaml(str(yaml_file), SimpleConfig)

    def test_load_yaml_missing_required_field(self, tmpdir):
        """should raise validation error when required field is missing"""
        yaml_content = """rule:
  name: test_rule
"""
        yaml_file = tmpdir / "missing_field.yaml"
        yaml_file.write(yaml_content)

        with pytest.raises(Exception):
            load_from_yaml(str(yaml_file), SimpleConfig)


@pytest.mark.unit
class TestYAMLLoaderIncludeDirectives:
    """Tests for YAML loading with include directives."""

    def test_load_with_single_absolute_include(self, tmpdir):
        """should load YAML with single absolute path include"""
        # create the included file
        included_content = """rule:
  name: included_rule
  value: base_value
"""
        included_file = tmpdir / "included.yaml"
        included_file.write(included_content)

        # create the main file that includes it
        main_content = f"""include:
  - {str(included_file)}
rule:
  value: overridden_value
"""
        main_file = tmpdir / "main.yaml"
        main_file.write(main_content)

        config, _ = load_from_yaml(str(main_file), SimpleConfig)

        # the main file should override the included file's value
        assert config.name == "included_rule"
        assert config.value == "overridden_value"

    def test_load_with_single_relative_include(self, tmpdir):
        """should load YAML with single relative path include"""
        # create the included file
        included_content = """rule:
  name: included_rule
  value: base_value
"""
        included_file = tmpdir / "included.yaml"
        included_file.write(included_content)

        # create the main file that includes it with relative path
        main_content = """include:
  - included.yaml
rule:
  value: overridden_value
"""
        main_file = tmpdir / "main.yaml"
        main_file.write(main_content)

        config, _ = load_from_yaml(str(main_file), SimpleConfig)

        # the main file should override the included file's value
        assert config.name == "included_rule"
        assert config.value == "overridden_value"

    def test_load_with_multiple_includes(self, tmpdir):
        """should load YAML with multiple includes in order"""
        # create first included file
        included1_content = """rule:
  name: first_rule
  value: first_value
"""
        included1_file = tmpdir / "included1.yaml"
        included1_file.write(included1_content)

        # create second included file
        included2_content = """rule:
  name: second_rule
  value: second_value
"""
        included2_file = tmpdir / "included2.yaml"
        included2_file.write(included2_content)

        # create the main file that includes both
        main_content = """include:
  - included1.yaml
  - included2.yaml
rule:
  value: final_value
"""
        main_file = tmpdir / "main.yaml"
        main_file.write(main_content)

        config, _ = load_from_yaml(str(main_file), SimpleConfig)

        # later includes and main file should override earlier ones
        assert config.name == "second_rule"
        assert config.value == "final_value"

    def test_load_with_nested_includes(self, tmpdir):
        """should load YAML with nested includes (include within include)"""
        # create the base file
        base_content = """rule:
  name: base_rule
  value: base_value
"""
        base_file = tmpdir / "base.yaml"
        base_file.write(base_content)

        # create a middle file that includes the base
        middle_content = """include:
  - base.yaml
rule:
  name: middle_rule
"""
        middle_file = tmpdir / "middle.yaml"
        middle_file.write(middle_content)

        # create the main file that includes the middle
        main_content = """include:
  - middle.yaml
rule:
  value: final_value
"""
        main_file = tmpdir / "main.yaml"
        main_file.write(main_content)

        config, _ = load_from_yaml(str(main_file), SimpleConfig)

        # should resolve all nested includes
        assert config.name == "middle_rule"
        assert config.value == "final_value"

    def test_load_with_subdirectory_relative_include(self, tmpdir):
        """should load YAML with relative include in subdirectory"""
        # create subdirectory
        subdir = tmpdir.mkdir("subdir")

        # create the included file in subdirectory
        included_content = """rule:
  name: included_rule
  value: included_value
"""
        included_file = subdir / "included.yaml"
        included_file.write(included_content)

        # create the main file that includes it with relative path
        main_content = """include:
  - subdir/included.yaml
rule:
  value: overridden_value
"""
        main_file = tmpdir / "main.yaml"
        main_file.write(main_content)

        config, _ = load_from_yaml(str(main_file), SimpleConfig)

        assert config.name == "included_rule"
        assert config.value == "overridden_value"

    def test_load_removes_include_directive_from_result(self, tmpdir):
        """should not include the include directive in the final merged result"""
        included_content = """rule:
  name: test_rule
  value: test_value
"""
        included_file = tmpdir / "included.yaml"
        included_file.write(included_content)

        main_content = """include:
  - included.yaml
"""
        main_file = tmpdir / "main.yaml"
        main_file.write(main_content)

        config, _ = load_from_yaml(str(main_file), SimpleConfig)

        # should successfully load without the include directive in the result
        assert config.name == "test_rule"
        assert config.value == "test_value"


@pytest.mark.unit
class TestYAMLLoaderInfiniteRecursionPrevention:
    """Tests for preventing infinite recursion in includes."""

    def test_prevent_circular_reference_direct(self, tmpdir):
        """should prevent direct circular reference (A includes A)"""
        # create a file that includes itself
        circular_content = """include:
  - circular.yaml
rule:
  name: circular_rule
  value: circular_value
"""
        circular_file = tmpdir / "circular.yaml"
        circular_file.write(circular_content)

        config, _ = load_from_yaml(str(circular_file), SimpleConfig)

        # should not cause infinite loop, file should only be loaded once
        assert config.name == "circular_rule"
        assert config.value == "circular_value"

    def test_prevent_circular_reference_indirect(self, tmpdir):
        """should prevent indirect circular reference (A includes B includes A)"""
        # create file B that will include A
        file_b_content = """include:
  - file_a.yaml
rule:
  name: file_b_rule
"""
        file_b = tmpdir / "file_b.yaml"
        file_b.write(file_b_content)

        # create file A that includes B
        file_a_content = """include:
  - file_b.yaml
rule:
  name: file_a_rule
  value: file_a_value
"""
        file_a = tmpdir / "file_a.yaml"
        file_a.write(file_a_content)

        config, _ = load_from_yaml(str(file_a), SimpleConfig)

        # should not cause infinite loop
        assert config.name == "file_a_rule"
        assert config.value == "file_a_value"

    def test_prevent_circular_reference_complex(self, tmpdir):
        """should prevent complex circular reference (A -> B -> C -> A)"""
        # create file C that will include A
        file_c_content = """include:
  - file_a.yaml
rule:
  value: file_c_value
"""
        file_c = tmpdir / "file_c.yaml"
        file_c.write(file_c_content)

        # create file B that includes C
        file_b_content = """include:
  - file_c.yaml
rule:
  name: file_b_rule
"""
        file_b = tmpdir / "file_b.yaml"
        file_b.write(file_b_content)

        # create file A that includes B
        file_a_content = """include:
  - file_b.yaml
rule:
  name: file_a_rule
"""
        file_a = tmpdir / "file_a.yaml"
        file_a.write(file_a_content)

        config, _ = load_from_yaml(str(file_a), SimpleConfig)

        # should not cause infinite loop
        assert config.name == "file_a_rule"
        assert config.value == "file_c_value"

    def test_same_file_included_multiple_times(self, tmpdir):
        """should only load a file once even if included multiple times"""
        # create a common base file
        base_content = """rule:
  name: base_rule
  value: base_value
"""
        base_file = tmpdir / "base.yaml"
        base_file.write(base_content)

        # create file A that includes base
        file_a_content = """include:
  - base.yaml
rule:
  name: file_a_rule
"""
        file_a = tmpdir / "file_a.yaml"
        file_a.write(file_a_content)

        # create file B that includes base
        file_b_content = """include:
  - base.yaml
"""
        file_b = tmpdir / "file_b.yaml"
        file_b.write(file_b_content)

        # create main file that includes both A and B (both include base)
        main_content = """include:
  - file_a.yaml
  - file_b.yaml
rule:
  value: main_value
"""
        main_file = tmpdir / "main.yaml"
        main_file.write(main_content)

        config, _ = load_from_yaml(str(main_file), SimpleConfig)

        # should successfully load without duplicating base
        assert config.name == "file_a_rule"
        assert config.value == "main_value"


@pytest.mark.unit
class TestYAMLLoaderErrorHandling:
    """Tests for error handling in the loader."""

    def test_include_directive_must_be_list(self, tmpdir):
        """should raise ValueError when include directive is not a list"""
        invalid_content = """include: not_a_list.yaml
rule:
  name: test_rule
  value: test_value
"""
        invalid_file = tmpdir / "invalid.yaml"
        invalid_file.write(invalid_content)

        with pytest.raises(ValueError, match="include directives must be a list"):
            load_from_yaml(str(invalid_file), SimpleConfig)

    def test_include_nonexistent_file(self, tmpdir):
        """should raise exception when included file does not exist"""
        main_content = """include:
  - nonexistent.yaml
rule:
  name: test_rule
  value: test_value
"""
        main_file = tmpdir / "main.yaml"
        main_file.write(main_content)

        with pytest.raises(Exception):
            load_from_yaml(str(main_file), SimpleConfig)

    def test_include_invalid_yaml_file(self, tmpdir):
        """should raise exception when included file has invalid YAML"""
        invalid_content = """rule:
  name: test
  [invalid yaml
"""
        invalid_file = tmpdir / "invalid.yaml"
        invalid_file.write(invalid_content)

        main_content = """include:
  - invalid.yaml
rule:
  value: test_value
"""
        main_file = tmpdir / "main.yaml"
        main_file.write(main_content)

        with pytest.raises(Exception):
            load_from_yaml(str(main_file), SimpleConfig)


@pytest.mark.unit
class TestYAMLLoaderMergeBehavior:
    """Tests for the merge behavior of the loader."""

    def test_later_values_override_earlier_values(self, tmpdir):
        """should override earlier values with later ones"""
        base_content = """rule:
  name: base_name
  value: base_value
"""
        base_file = tmpdir / "base.yaml"
        base_file.write(base_content)

        override_content = """include:
  - base.yaml
rule:
  value: overridden_value
"""
        override_file = tmpdir / "override.yaml"
        override_file.write(override_content)

        config, _ = load_from_yaml(str(override_file), SimpleConfig)

        # name should come from base, value should be overridden
        assert config.name == "base_name"
        assert config.value == "overridden_value"

    def test_main_file_has_final_say(self, tmpdir):
        """should give main file final say in merged values"""
        included1_content = """rule:
  name: included1
  value: value1
"""
        included1_file = tmpdir / "included1.yaml"
        included1_file.write(included1_content)

        included2_content = """rule:
  name: included2
  value: value2
"""
        included2_file = tmpdir / "included2.yaml"
        included2_file.write(included2_content)

        main_content = """include:
  - included1.yaml
  - included2.yaml
rule:
  name: main_name
  value: main_value
"""
        main_file = tmpdir / "main.yaml"
        main_file.write(main_content)

        config, _ = load_from_yaml(str(main_file), SimpleConfig)

        # both values should come from main file
        assert config.name == "main_name"
        assert config.value == "main_value"

    def test_include_order_matters(self, tmpdir):
        """should respect the order of includes when merging"""
        first_content = """rule:
  name: first
  value: first_value
"""
        first_file = tmpdir / "first.yaml"
        first_file.write(first_content)

        second_content = """rule:
  name: second
  value: second_value
"""
        second_file = tmpdir / "second.yaml"
        second_file.write(second_content)

        # test order 1: first, then second
        main1_content = """include:
  - first.yaml
  - second.yaml
"""
        main1_file = tmpdir / "main1.yaml"
        main1_file.write(main1_content)

        config1, _ = load_from_yaml(str(main1_file), SimpleConfig)
        assert config1.name == "second"
        assert config1.value == "second_value"

        # test order 2: second, then first
        main2_content = """include:
  - second.yaml
  - first.yaml
"""
        main2_file = tmpdir / "main2.yaml"
        main2_file.write(main2_content)

        config2, _ = load_from_yaml(str(main2_file), SimpleConfig)
        assert config2.name == "first"
        assert config2.value == "first_value"

    def test_nested_includes_resolve_depth_first(self, tmpdir):
        """should resolve nested includes depth-first before parent overrides"""
        # deepest level
        deep_content = """rule:
  name: deep
  value: deep_value
"""
        deep_file = tmpdir / "deep.yaml"
        deep_file.write(deep_content)

        # middle level includes deep and overrides name
        middle_content = """include:
  - deep.yaml
rule:
  name: middle
"""
        middle_file = tmpdir / "middle.yaml"
        middle_file.write(middle_content)

        # top level includes middle and overrides value
        top_content = """include:
  - middle.yaml
rule:
  value: top_value
"""
        top_file = tmpdir / "top.yaml"
        top_file.write(top_content)

        config, _ = load_from_yaml(str(top_file), SimpleConfig)

        # name should be from middle (which overrode deep)
        # value should be from top (which overrode deep)
        assert config.name == "middle"
        assert config.value == "top_value"


@pytest.mark.unit
class TestYAMLLoaderComplexScenarios:
    """Tests for complex real-world scenarios."""

    def test_common_base_with_multiple_specific_hunts(self, tmpdir):
        """should support common base configuration for multiple specific hunts"""
        # common base settings
        common_content = """rule:
  name: will_be_overridden
  value: common_value
"""
        common_file = tmpdir / "common.yaml"
        common_file.write(common_content)

        # specific hunt 1
        hunt1_content = """include:
  - common.yaml
rule:
  name: hunt1
"""
        hunt1_file = tmpdir / "hunt1.yaml"
        hunt1_file.write(hunt1_content)

        # specific hunt 2
        hunt2_content = """include:
  - common.yaml
rule:
  name: hunt2
"""
        hunt2_file = tmpdir / "hunt2.yaml"
        hunt2_file.write(hunt2_content)

        # load both hunts
        config1, _ = load_from_yaml(str(hunt1_file), SimpleConfig)
        config2, _ = load_from_yaml(str(hunt2_file), SimpleConfig)

        # both should have common value but different names
        assert config1.name == "hunt1"
        assert config1.value == "common_value"
        assert config2.name == "hunt2"
        assert config2.value == "common_value"

    def test_layered_configuration_inheritance(self, tmpdir):
        """should support layered configuration (base -> category -> specific)"""
        # base layer
        base_content = """rule:
  name: base
  value: base_value
"""
        base_file = tmpdir / "base.yaml"
        base_file.write(base_content)

        # category layer
        category_content = """include:
  - base.yaml
rule:
  name: category
"""
        category_file = tmpdir / "category.yaml"
        category_file.write(category_content)

        # specific layer
        specific_content = """include:
  - category.yaml
rule:
  name: specific
"""
        specific_file = tmpdir / "specific.yaml"
        specific_file.write(specific_content)

        config, _ = load_from_yaml(str(specific_file), SimpleConfig)

        assert config.name == "specific"
        assert config.value == "base_value"

    def test_empty_include_list(self, tmpdir):
        """should handle empty include list gracefully"""
        content = """include: []
rule:
  name: test_rule
  value: test_value
"""
        yaml_file = tmpdir / "test.yaml"
        yaml_file.write(content)

        config, _ = load_from_yaml(str(yaml_file), SimpleConfig)

        assert config.name == "test_rule"
        assert config.value == "test_value"
