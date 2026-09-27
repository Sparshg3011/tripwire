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


def test_duplicate_tool_rejected(tmp_path):
    # last one wins in plain yaml, and here the last one is the loose one
    p = write(
        tmp_path,
        "version: 1\ntools:\n  send_email: {action: block}\n  send_email: {action: allow}\n",
    )
    with pytest.raises(PolicyError, match=r"(?s)duplicate key 'send_email'.*line 4, column 3"):
        load_policy(p)


def test_duplicate_nested_key_rejected(tmp_path):
    p = write(
        tmp_path,
        "version: 1\n"
        "tools:\n"
        "  send_email:\n"
        "    action: allow\n"
        "    constraints:\n"
        '      to: {regex: "^a@corp$", regex: ".*"}\n',
    )
    with pytest.raises(PolicyError, match=r"(?s)duplicate key 'regex'.*line 6, column 31"):
        load_policy(p)


def test_merge_keys_may_still_be_overridden(tmp_path):
    p = write(
        tmp_path,
        "version: 1\n"
        "tools:\n"
        "  send_email: &gated {action: require_approval, limits: {per_session: 3}}\n"
        "  http_post: {<<: *gated, action: block}\n",
    )
    policy = load_policy(p)
    assert policy.tools["http_post"].action == "block"
    assert policy.tools["http_post"].limits.per_session == 3


def test_second_merge_key_rejected(tmp_path):
    # yaml applies both and the later one wins, so the strict rule a reader
    # sees first is not the one in force
    p = write(
        tmp_path,
        "version: 1\n"
        "tools:\n"
        "  send_email: &strict {action: require_approval}\n"
        "  read_email: &loose {action: allow}\n"
        "  forward_email:\n"
        "    <<: *strict\n"
        "    <<: *loose\n",
    )
    with pytest.raises(PolicyError, match=r"(?s)duplicate key '<<'.*line 7, column 5"):
        load_policy(p)


def test_one_merge_key_may_merge_several_mappings(tmp_path):
    # a list is how to merge more than one, and the first one listed wins
    p = write(
        tmp_path,
        "version: 1\n"
        "tools:\n"
        "  send_email: &strict {action: require_approval}\n"
        "  read_email: &loose {action: allow, reason: fine}\n"
        "  forward_email: {<<: [*strict, *loose]}\n",
    )
    rule = load_policy(p).tools["forward_email"]
    assert rule.action == "require_approval"
    assert rule.reason == "fine"


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
