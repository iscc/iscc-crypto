"""Test README code examples to ensure they work correctly."""

from mktestdocs import check_md_file


def test_readme_examples():
    # type: () -> None
    """Test that all Python code examples in README.md execute successfully."""
    check_md_file("README.md", memory=True)
