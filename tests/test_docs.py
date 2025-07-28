"""Test Python code blocks in markdown documentation."""

import doctest
import pathlib
import pytest
import re
import types
from mktestdocs import check_md_file


@pytest.mark.parametrize("fpath", [pathlib.Path("docs/tutorials/getting-started.md")], ids=str)
def test_tutorial_code_blocks(fpath):
    # type: (pathlib.Path) -> None
    """
    Test that all Python code blocks in tutorial markdown files execute without errors.

    :param fpath: Path to markdown file to test
    """
    check_md_file(fpath=fpath, memory=True)


def test_readme_examples():
    # type: () -> None
    """Test that all Python code examples in README.md execute successfully."""
    # Read the README file
    with open("README.md", "r") as f:
        readme_content = f.read()

    # Extract Python and pycon code blocks with doctest format
    python_blocks = re.findall(r"```(?:python|pycon)\n(.*?)\n```", readme_content, re.DOTALL)

    # Test each Python block that contains doctest examples
    for block in python_blocks:
        if ">>>" in block:
            # Create a temporary module-like object for doctest
            temp_module = types.ModuleType("temp_readme_test")
            temp_module.__doc__ = block

            # Run doctest on the block
            results = doctest.testmod(temp_module, verbose=True, report=True)

            # Assert no failures
            assert results.failed == 0, f"Doctest failed with {results.failed} failures in README example"
