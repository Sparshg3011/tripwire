import importlib.metadata

import pytest

from tripwire.cli import main


def test_version_is_the_installed_distributions(capsys):
    with pytest.raises(SystemExit) as exited:
        main(["--version"])
    assert exited.value.code == 0
    assert capsys.readouterr().out == f"tripwire {importlib.metadata.version('tripwire-agent')}\n"
