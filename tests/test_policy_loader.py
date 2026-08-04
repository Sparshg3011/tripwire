import pytest

from tripwire.policy import PolicyError, load_policy


def write(tmp_path, text):
    p = tmp_path / "policy.yaml"
    p.write_text(text)
    return p


def test_load_valid(tmp_path):
    p = write(tmp_path, "version: 1\ntools:\n  rm: {action: block}\n")
    policy = load_policy(p)
    assert policy.tools["rm"].action == "block"


def test_missing_file():
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy("/nonexistent/policy.yaml")


def test_broken_yaml(tmp_path):
    p = write(tmp_path, "version: 1\n  bad indent: [unclosed\n")
    with pytest.raises(PolicyError, match="invalid yaml"):
        load_policy(p)


def test_yaml_that_is_not_a_mapping(tmp_path):
    p = write(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(PolicyError, match="mapping"):
        load_policy(p)


def test_validation_error_names_the_path(tmp_path):
    p = write(tmp_path, "version: 1\ntools:\n  send_email: {action: maybe}\n")
    with pytest.raises(PolicyError, match="tools.send_email.action"):
        load_policy(p)


def test_error_message_is_readable(tmp_path):
    p = write(tmp_path, "version: 1\ntools:\n  a: {action: block, extra_key: 1}\n")
    try:
        load_policy(p)
    except PolicyError as e:
        # one header line + one line per problem, each naming its location
        assert "invalid policy" in str(e)
        assert "extra_key" in str(e)
    else:
        pytest.fail("should not have loaded")
