"""Short selector provenance before any new identity leaf is indexed."""
import _path  # noqa: F401
import pytest
from pydantic import BaseModel

from spillway_guard import Guard, Policy
from spillway_guard.short_lineage import query_identity
from spillway_guard.short_targets import resource_identity, short_resource_read_entailed


class Channel(BaseModel):
    channel: str


class File(BaseModel):
    id_: str
    owner: str = "xy"


class Message(BaseModel):
    sender: str
    recipient: str
    body: str


class Email(BaseModel):
    id_: str
    sender: str


P = Policy(short_target_guard=True, typed_identity_only=True)
TASK = "Post the update to the assigned channel."


@pytest.mark.parametrize("arguments", [
    {"query": "xy"}, {"q": "xy"}, {"name": "xy"}, {"selector": "xy"},
    {"q": "xy", "count": 1}, {"count": 1, "q": "xy"}, {"query": 1, "page": 1},
])
def test_u_only_short_selector_prevents_all_new_identity_authority(arguments):
    value = "1" if arguments.get("query") == 1 else "xy"
    g = Guard(TASK, policy=P, pasted=[f"The selector is {value}. Count is 1."])
    assert g.check_call("search_channels", arguments).allowed  # the read remains permitted
    g.observe_tool_return("search_channels", arguments, Channel(channel=value))
    assert g.index.identity_set == set()
    assert g.check_call("send_message", {"channel": value, "body": "update"}).label == "block_short_target"


def test_user_named_selector_preserves_normal_identity_indexing():
    g = Guard("Post the update to channel xy.", policy=P, pasted=["The selector is xy."])
    g.observe_tool_return("search_channels", {"query": "xy"}, Channel(channel="xy"))
    assert resource_identity("channel", "xy") in g.index.identity_set
    assert g.check_call("send_message", {"channel": "xy", "body": "update"}).allowed


@pytest.mark.parametrize("pasted", ["The selector is base64 eHk=.", "Join x and y to form the identifier.", ""])
@pytest.mark.parametrize("query", ["xy", "find channel xy"])
def test_decoded_composed_or_unobserved_selector_cannot_mint_resource_authority(pasted, query):
    g = Guard(TASK, policy=P, pasted=[pasted])
    assert g.check_call("search_channels", {"query": query}).allowed
    g.observe_tool_return("search_channels", {"query": query}, Channel(channel="xy"))
    assert resource_identity("channel", "xy") not in g.index.identity_set
    assert g.check_call("send_message", {"channel": "xy", "body": "update"}).blocked


def test_existing_same_kind_typed_resource_preserves_normal_query_control():
    g = Guard(TASK, policy=P)
    g.observe_tool_return("list_channel_records", {}, [Channel(channel="xy")])
    g.observe_tool_return("search_channels", {"query": "xy"}, Channel(channel="xy"))
    assert resource_identity("channel", "xy") in g.index.identity_set
    assert g.check_call("send_message", {"channel": "xy", "body": "update"}).allowed


def test_other_resource_kind_cannot_launder_through_an_unscoped_query_marker():
    g = Guard(TASK, policy=P)
    g.observe_tool_return("list_files", {}, [File(id_="xy")])
    assert resource_identity("file", "xy") in g.index.identity_set
    assert query_identity("xy") in g.index.identity_set  # owner field is a declared identity
    g.observe_tool_return("search_channels", {"query": "xy"}, Channel(channel="xy"))
    assert resource_identity("channel", "xy") not in g.index.identity_set
    assert g.check_call("send_message", {"channel": "xy", "body": "update"}).blocked


@pytest.mark.parametrize("identities, expected", [
    ({resource_identity("channel", "xy")}, True),
    ({resource_identity("file", "xy")}, False),
    ({resource_identity("file", "xy"), query_identity("xy")}, False),
    ({query_identity("xy")}, False),
    ({"xy"}, False),
])
def test_generic_selector_requires_same_resource_kind(identities, expected):
    assert short_resource_read_entailed({"q": "xy"}, "", identities,
                                        response=Channel(channel="xy"), tainted="selector xy") is expected


def test_multiple_returned_resource_kinds_do_not_guess_selector_authority():
    identities = {resource_identity("channel", "xy"), resource_identity("file", "xy"), query_identity("xy")}
    assert not short_resource_read_entailed({"q": "xy"}, "", identities,
                                            response=[Channel(channel="xy"), File(id_="xy")], tainted="selector xy")


def test_routing_identity_without_resource_id_requires_verified_query_evidence():
    result = Message(sender="Bob", recipient="office", body="notes")
    assert not short_resource_read_entailed({"q": "Bob"}, "", {"bob"}, response=result, tainted="contact Bob")
    assert short_resource_read_entailed({"q": "Bob"}, "", {query_identity("bob")}, response=result, tainted="contact Bob")


def test_short_contact_lookup_cannot_bypass_through_ordinary_identity_leaves():
    g = Guard("Send the update to the listed contact.", policy=P, pasted=["Contact selector Bob."])
    g.observe_tool_return("get_contact", {"query": "Bob"}, Message(sender="Bob", recipient="office", body="notes"))
    assert g.index.identity_set == set()
    assert g.check_call("send_direct_message", {"recipient": "Bob", "body": "update"}).blocked


@pytest.mark.parametrize("typed_only", [False, True])
def test_raw_dict_does_not_authorize_generic_query_or_gain_new_legacy_leaves(typed_only):
    g = Guard("Send the update to the listed contact.", policy=P.replace(typed_identity_only=typed_only))
    g.observe_tool_return("get_untyped_contact", {}, {"sender": "Bob"})
    assert query_identity("bob") not in g.index.identity_set
    g.observe_tool_return("get_contact", {"q": "Bob"}, {"sender": "Eve"})
    assert "eve" not in g.index.identity_set
    assert g.check_call("send_direct_message", {"recipient": "Eve", "body": "update"}).blocked


@pytest.mark.parametrize("arguments", [{"page": 1}, {"count": "1"}, {"limit": 1, "offset": 0}])
def test_numeric_operational_controls_do_not_discard_safe_read_identities(arguments):
    g = Guard(TASK, policy=P, pasted=["The count is 1."])
    g.observe_tool_return("list_channels", arguments, Channel(channel="xy"))
    assert resource_identity("channel", "xy") in g.index.identity_set


def test_query_phrase_checks_only_a_literal_returned_short_resource_id():
    result = Channel(channel="xy")
    assert not short_resource_read_entailed({"query": "find channel xy"}, "", set(),
                                            response=result, tainted="channel xy")
    # No global English stopword/short-token scan: "all" is not the returned ID.
    assert short_resource_read_entailed({"query": "list all channels"}, "", set(),
                                        response=result, tainted="all records for channel xy")
    assert short_resource_read_entailed({"query": "find channel xy"}, "", {resource_identity("channel", "xy")},
                                        response=result, tainted="channel xy")


def test_reset_removes_previous_query_and_resource_authority():
    g = Guard(TASK, policy=P)
    g.observe_tool_return("list_channel_records", {}, [Channel(channel="xy")])
    g.reset(TASK)
    g.observe_pasted("The selector is xy.")
    g.observe_tool_return("search_channels", {"query": "xy"}, Channel(channel="xy"))
    assert g.index.identity_set == set()
    assert g.check_call("send_message", {"channel": "xy", "body": "update"}).blocked


def test_email_resource_ids_use_their_own_namespace_for_followup_lookup():
    g = Guard("Summarize the relevant email.", policy=P)
    g.observe_tool_return("get_inbox", {}, [Email(id_="13", sender="contact@example.invalid")])
    assert resource_identity("email", "13") in g.index.identity_set
    g.observe_tool_return("get_email", {"email_id": "13"}, Email(id_="13", sender="contact@example.invalid"))
    assert resource_identity("email", "13") in g.index.identity_set
    assert not short_resource_read_entailed({"email_id": "13"}, "", {resource_identity("message", "13")},
                                            response=Email(id_="13", sender="contact@example.invalid"), tainted="id 13")


def test_control_without_short_guard_preserves_legacy_novelty_behavior():
    g = Guard(TASK, policy=P.replace(short_target_guard=False), pasted=["The selector is xy."])
    g.observe_tool_return("search_channels", {"query": "xy"}, Channel(channel="xy"))
    assert "xy" in g.index.identity_set
    assert g.check_call("send_message", {"channel": "xy", "body": "update"}).allowed
