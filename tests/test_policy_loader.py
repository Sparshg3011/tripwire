import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from tripwire.cli import main
from tripwire.policy import PolicyError, load_policy
from tripwire.policy.loader import _UniqueKeyLoader, policy_warnings


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


@pytest.mark.parametrize(
    "rule",
    [
        "{<<: {<<: *strict, <<: *loose}}",
        "{<<: {action: block, action: allow}}",
        "{<<: [{action: block, action: allow}]}",
        "{<<: [*strict, {<<: *strict, <<: *loose}]}",
    ],
)
def test_a_mapping_that_is_only_merged_is_checked_too(tmp_path, rule):
    # yaml copies a merge source's pairs into the target without ever
    # building the source as a mapping of its own
    p = write(
        tmp_path,
        "version: 1\n"
        "tools:\n"
        "  send_email: &strict {action: require_approval}\n"
        "  read_email: &loose {action: allow}\n"
        f"  forward_email: {rule}\n",
    )
    with pytest.raises(PolicyError, match="duplicate key"):
        load_policy(p)


def test_an_anchor_defined_in_a_merge_is_checked_where_it_is_defined(tmp_path):
    p = write(
        tmp_path,
        "version: 1\n"
        "tools:\n"
        "  send_email: {<<: &base {action: block, action: allow}}\n"
        "  forward_email: {<<: *base}\n",
    )
    with pytest.raises(PolicyError, match=r"(?s)duplicate key 'action'.*line 3, column 42"):
        load_policy(p)


def test_a_merged_anchor_may_override_its_own_merge_and_be_reused(tmp_path):
    # merging rewrites the source in place, so by the time *base is built
    # as a rule of its own, the key it overrode sits right next to it
    p = write(
        tmp_path,
        "version: 1\n"
        "tools:\n"
        "  send_email: &gated {action: require_approval}\n"
        "  http_post:\n"
        "    <<: &base\n"
        "      <<: *gated\n"
        "      action: block\n"
        "  delete_file: *base\n",
    )
    policy = load_policy(p)
    assert policy.tools["http_post"].action == "block"
    assert policy.tools["delete_file"].action == "block"


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


@st.composite
def flow_mappings(draw, anchors, depth=0):
    # keys often repeated, mappings often anchored, merged and aliased;
    # an anchor is only offered once the mapping it names is written out
    def mapping():
        if anchors and draw(st.booleans()):
            return "*" + draw(st.sampled_from(anchors))
        return draw(flow_mappings(anchors, depth + 1)) if depth < 2 else "{}"

    pairs = []
    for key in draw(st.lists(st.sampled_from(["a", "b", "c", "<<"]), max_size=3)):
        if key != "<<":
            value = mapping() if draw(st.booleans()) else "1"
        elif draw(st.booleans()):
            value = mapping()
        else:
            value = "[" + ", ".join(mapping() for _ in range(draw(st.integers(1, 2)))) + "]"
        pairs.append(f"{key}: {value}")
    text = "{" + ", ".join(pairs) + "}"
    if draw(st.booleans()):
        anchors.append(f"m{len(anchors)}")
        text = f"&{anchors[-1]} {text}"
    return text


documents = st.builds(list).flatmap(flow_mappings)


def repeats_a_key(text):
    # read off the nodes as written, before any merge rewrites them
    seen, todo = set(), [yaml.compose(text)]
    while todo:
        node = todo.pop()
        if node in seen:
            continue
        seen.add(node)
        if isinstance(node, yaml.MappingNode):
            keys = ["<<" if k.tag == "tag:yaml.org,2002:merge" else k.value for k, _ in node.value]
            if len(set(keys)) < len(keys):
                return True
            todo.extend(v for _, v in node.value)
        elif isinstance(node, yaml.SequenceNode):
            todo.extend(node.value)
    return False


@given(text=documents)
def test_refused_exactly_when_a_mapping_repeats_a_key(text):
    try:
        loaded = yaml.load(text, Loader=_UniqueKeyLoader)
    except yaml.constructor.ConstructorError:
        assert repeats_a_key(text)
    else:
        assert not repeats_a_key(text)
        assert loaded == yaml.safe_load(text)


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


def test_an_argument_contract_error_names_the_path(tmp_path):
    p = write(tmp_path, "version: 1\ntools:\n  send: {action: allow, args: {to: recipient}}\n")
    with pytest.raises(PolicyError, match="tools.send.args.to.role"):
        load_policy(p)


ANCHORED = """
version: 1
tools:
  send_email: {action: allow, args: {to: target, body: content}}
  post: {action: allow}
flows:
  - {when: context_tainted, tools: [send_email, post, shell], action: block, unless: anchored}
  - {when: context_tainted, tools: [post], action: require_approval}
"""


def test_a_tool_an_anchored_flow_can_never_discharge_is_warned_about(tmp_path):
    warning = "flows[0] says unless: anchored, but {} has no args contract, so the flow applies"
    warnings = policy_warnings(load_policy(write(tmp_path, ANCHORED)))
    assert [w.split(" to every")[0] for w in warnings] == [
        warning.format("post"),
        warning.format("shell"),
    ]


def test_validate_prints_the_warnings_and_still_passes(tmp_path, capsys):
    main(["validate", str(write(tmp_path, ANCHORED))])
    out, err = capsys.readouterr()
    assert out.startswith("ok: ")
    assert err.count("warning: ") == 2


def test_a_v1_policy_has_nothing_to_warn_about(reference_policy):
    assert policy_warnings(reference_policy) == []
