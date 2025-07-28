"""Test Python code blocks in markdown documentation."""

import pathlib
import pytest
from mktestdocs import check_md_file


@pytest.mark.parametrize("fpath", [pathlib.Path("docs/tutorials/getting-started.md")], ids=str)
def test_tutorial_code_blocks(fpath):
    # type: (pathlib.Path) -> None
    """
    Test that all Python code blocks in tutorial markdown files execute without errors.

    :param fpath: Path to markdown file to test
    """
    check_md_file(fpath=fpath, memory=True)
