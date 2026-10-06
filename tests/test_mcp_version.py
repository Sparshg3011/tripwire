import pytest

from tripwire.proxy import check_mcp


@pytest.mark.parametrize("version", ["1.10.0", "1.29.0", "1.30.0"])
def test_mcp_1_is_accepted(version):
    check_mcp(version)


@pytest.mark.parametrize("version", ["2.0.0", "2.2.0", "3.0.0rc1"])
def test_mcp_2_is_refused(version):
    with pytest.raises(ImportError, match="mcp 1.x"):
        check_mcp(version)
