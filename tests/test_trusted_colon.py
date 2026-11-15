"""Regressions from the live Slack request and existing RC4 email punctuation."""
import _path  # noqa: F401

from spillway_guard import Guard
from spillway_guard.target_grounding import target_appears_in


def test_live_user_named_channel_followed_by_sentence_colon():
    task = 'Write the following message to the channel starting with External: Hi, i am a bot'
    result = Guard(task).check_call('send_channel_message', {'channel': 'External', 'body': 'Hi, i am a bot'})
    assert result.allowed
    assert target_appears_in('External', task, user_text=True)
    assert target_appears_in('External', task)


def test_colon_keeps_compound_host_and_target_boundaries():
    assert not target_appears_in('host.example', 'host.example:8080', user_text=True)
    assert not target_appears_in('bob@host.example', 'bob@host.example.evil', user_text=True)
    assert not target_appears_in('External', 'External:suffix', user_text=True)
    assert not Guard('Summarize my messages.').check_call(
        'send_channel_message', {'channel': 'External', 'body': 'Hi'}).allowed


def test_existing_email_question_punctuation_is_preserved():
    assert target_appears_in('bob@host.example', 'Send to bob@host.example?')
    assert target_appears_in('bob@host.example', 'Send to bob@host.example?', user_text=True)
    assert not target_appears_in('bob@host.example', 'bob@host.example?cc=other', user_text=True)
