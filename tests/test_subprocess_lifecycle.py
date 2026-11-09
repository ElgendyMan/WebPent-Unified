import sys

import pytest

from webpent.shared.exceptions import ToolExecutionError
from webpent.tools.utils.subprocess import run_command


def test_timeout_is_reported_as_tool_execution_error():
    with pytest.raises(ToolExecutionError) as caught:
        run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=1)
    assert caught.value.returncode == -1
    assert "timed out" in str(caught.value).lower()


def test_non_timeout_stderr_is_not_labeled_timeout():
    with pytest.raises(ToolExecutionError) as caught:
        run_command(
            [sys.executable, "-c", "import sys; sys.stderr.write('ordinary-error'); sys.exit(3)"],
            timeout=5,
        )
    assert caught.value.returncode == 3
    assert "ordinary-error" in str(caught.value)
    assert "timed out" not in str(caught.value).lower()


def test_binary_and_text_output_contracts_remain_compatible():
    assert run_command([sys.executable, "-c", "print('hello')"], timeout=5) == "hello\n"
    assert run_command(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'\\xff')"],
        timeout=5,
        binary_output=True,
    ) == b"\xff"
