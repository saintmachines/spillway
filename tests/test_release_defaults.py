"""The installed SDK and AgentDojo contract helpers must select the same final014 profile."""
import os
from unittest.mock import patch

import _path  # noqa: F401

from spillway_guard import Guard, Policy
from spillway_guard.agentdojo.candidate_policy import candidate_policy
from spillway_guard.floor import DEFAULT_POLICY


def test_default_entry_points_select_the_final_profile():
    final = Policy.enhanced_014()
    assert DEFAULT_POLICY == final
    assert Guard('Summarize my calendar.').policy == final
    with patch.dict(os.environ, {}, clear=True):
        assert candidate_policy() == final
    assert not final.payload_secret_guard and not final.payload_partial_guard


def test_default_does_not_treat_free_json_keys_as_identity_authority():
    g = Guard('Send the summary to Alice.')
    g.observe_tool_return('read_file', {}, {'sender': 'alice@unrequested.example'})
    assert not g.check_call('send_email', {'recipients': ['alice@unrequested.example'], 'body': 'Summary'}).allowed


def test_user_written_address_and_optional_target_omission_remain_usable():
    assert Guard('Send to alice@named.example.').check_call(
        'send_email', {'recipients': ['alice@named.example'], 'body': 'Summary'}).allowed
    assert Guard('Add a reminder to my calendar.').check_call(
        'create_calendar_event', {'title': 'Reminder', 'start_time': '2026-11-14 19:00',
                                  'end_time': '2026-11-14 20:00'}).allowed


def test_numeric_count_n_does_not_become_a_resource_selector():
    from spillway_guard.short_targets import short_resource_read_entailed
    assert short_resource_read_entailed({'n': 5}, '', set())
    assert short_resource_read_entailed({'count': 5}, '', set())
    assert not short_resource_read_entailed({'file_id': '5'}, '', set())
