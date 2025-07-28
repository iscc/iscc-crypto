"""Test README code examples to ensure they work correctly."""

import doctest
import re


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
            import types

            temp_module = types.ModuleType("temp_readme_test")
            temp_module.__doc__ = block

            # Run doctest on the block
            results = doctest.testmod(temp_module, verbose=True, report=True)

            # Assert no failures
            assert results.failed == 0, f"Doctest failed with {results.failed} failures in README example"
