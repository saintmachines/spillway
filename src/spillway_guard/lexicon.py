"""Role lexicon: the vocabulary the floor uses to classify a tool name and an argument name.

The values come from the reference implementation, the final build the paper evaluated (the gate module
and the taint-gate module of the evaluation harness), and CHANGELOG.md lists the additions. The lexicon decides *roles* only: which
tool names are read-only, side-effecting, destructive or access-granting, and which argument
names route a side effect to a target or grant a principal. It never contains an attack string.

The defaults are the AgentDojo settings of the paper. ``Lexicon.for_agentdyn()`` returns the
AgentDyn-suite settings (token-set verb classification and the extra identity-role target args).
``Lexicon.extend(...)`` returns a copy with extra entries for a new tool surface.
"""

from __future__ import annotations

import dataclasses
import re
from dataclasses import dataclass
from typing import FrozenSet, Tuple

# --- tool-name verb classes (taint-gate module) -------------------------------------------------
# A tool is read-only iff it is NOT a known write prefix AND matches a read prefix.
READ_PREFIXES: Tuple[str, ...] = ("get_", "search_", "list_", "find_", "read_", "check_",
                                  "retrieve_", "show_", "view_", "query_", "lookup_")
WRITE_PREFIXES: Tuple[str, ...] = ("send_", "delete_", "create_", "share_", "append_", "cancel_",
                                   "reschedule_", "add_", "update_", "modify_", "remove_", "book_",
                                   "purchase_", "transfer_", "pay_", "post_", "set_", "schedule_",
                                   "edit_", "write_", "forward_", "reply_")
# Destructive/irreversible ops: the harm is the action itself (not data routing).
DESTRUCTIVE_PREFIXES: Tuple[str, ...] = ("delete_", "cancel_", "remove_", "clear_", "trash_",
                                         "archive_", "unshare_", "revoke_", "discard_", "drop_")
DESTRUCT_INTENT: Tuple[str, ...] = ("delet", "remov", "cancel", "clear", "trash", "discard",
                                    "unsubscrib", "archiv", "revoke", "empty", "clean up", "get rid")
# An intent stem counts as a whole word with these endings ("cancelled" yes, "cancellation policy" no), and not
# when a negation stands up to two words before it ("do not delete", "without deleting").
INTENT_TAIL = r"(?:e|es|s|d|ed|led|ing|ling|al|ion|ions)?\b"
INTENT_NEGATED = re.compile(r"(?:\bnot|\bnever|\bwithout|\bavoid|\bdont|n['\u2019]t)\s+(?:\w+\s+){0,2}$")
# Access-grant verbs (constructive access-control mutation that grants a resource to a principal).
GRANT_PREFIXES: Tuple[str, ...] = ("add_", "invite_", "grant_", "share_", "promote_", "authorize_",
                                   "subscribe_", "assign_", "enroll_", "register_", "give_")

# --- argument-name roles ----------------------------------------------------------------------
# Argument names that ROUTE/TARGET a side effect (where an exfil attack redirects the data).
# Token-matched so "to" matches arg `to` but not `topic`.
TARGET_ARG_HINTS: FrozenSet[str] = frozenset({
    "recipient", "recipients", "to", "cc", "bcc", "email", "emails", "address",
    "addresses", "url", "account", "iban", "destination", "dest", "phone",
    "sender", "participant", "participants", "channel",
    "attendee", "attendees", "invitee", "invitees", "guest", "guests", "shared_with",
})
# A field or argument name holding one of these words carries prose, even next to a target word
# (email_body, channel_description, to_do). It is never a target and never an identity role.
FREE_TEXT_WORDS: FrozenSet[str] = frozenset({
    "body", "content", "description", "subject", "title", "text", "note", "notes", "comment",
    "comments", "message", "summary", "topic", "do", "how", "self",
})
# AgentDyn (github/shopping/dailylife) identity-role target args; EMPTY for AgentDojo.
AGENTDYN_TARGET_HINTS: FrozenSet[str] = frozenset({
    "repo_name", "username", "file_id", "func_name", "event_id", "password",
})
# Principal / access-grant params (who is granted access); taint-gate module, AgentDyn mode only.
PRINCIPAL_HINTS: FrozenSet[str] = frozenset({"collaborator_email", "new_owner", "assignee",
                                             "grantee", "member", "owner"})
# Credential-typed params (a schema category, not a hand list of attack strings).
CREDENTIAL_HINTS: FrozenSet[str] = frozenset({"otp", "token", "password", "passwd", "secret",
                                              "ssh_key", "sshkey", "api_key", "apikey", "key",
                                              "code", "pin", "credential"})
CREDENTIAL_ROLE: FrozenSet[str] = frozenset({"otp", "token", "password", "passwd", "secret", "ssh_key",
                                             "sshkey", "api_key", "apikey", "key", "code", "pin", "credential"})
CRED_INSTALL_VERBS: FrozenSet[str] = frozenset({"add", "update", "set", "register", "change", "reset", "rotate", "create"})
CRED_NOUNS: Tuple[str, ...] = ("ssh_key", "sshkey", "password", "passwd", "api_key", "apikey", "credential", "secret", "token")
CRED_INSTALL_INTENT: Tuple[str, ...] = ("add ssh", "new ssh", "add key", "register key", "update password",
                                        "change password", "reset password", "set password", "rotate", "new password")
# Entity-principal argument names of an access-grant call (the granted party).
PRINCIPAL_ARG_HINTS: FrozenSet[str] = frozenset({
    "user", "users", "member", "members", "participant", "participants",
    "invitee", "invitees", "assignee", "assignees", "person", "people",
    "contact", "contacts", "username", "user_name", "member_name", "attendee",
    "attendees", "collaborator", "collaborators",
})
# AgentDyn identity/routing FIELD names whose values index as trusted identities (free-text
# fields such as body/subject/description/content/notes/title/comment are deliberately absent).
AGENTDYN_ID_FIELDS: FrozenSet[str] = frozenset({
    "sender", "recipient", "recipients", "email", "email_address", "user_email",
    "username", "user", "owner", "author", "from", "to", "cc", "bcc",
    "collaborator_email", "new_owner_email", "account", "member", "members",
    "participant", "participants", "contact", "assignee",
    "repository", "repositories", "repos", "repo", "repo_name",
})
# Self-directed writes (no external recipient) routed to the integrity tier instead of the
# exfil target branch, except for their recipient-like args.
SELF_WRITE_TOOLS: FrozenSet[str] = frozenset({"create_calendar_event", "reschedule_calendar_event",
                                              "update_calendar_event", "create_file", "create_dir", "append_to_file"})
SELF_WRITE_RECIPIENT_ARGS: FrozenSet[str] = frozenset({"participants", "participant", "attendees", "attendee", "shared_with",
                                                       "invitees", "invitee", "guests", "emails", "email"})
# Slack message sinks (a phishing URL in a message BODY is a non-target payload).
SLACK_MSG_SINKS: FrozenSet[str] = frozenset({"send_direct_message", "send_channel_message"})
# url/uri-like argument names (read-fetch source vs egress target).
FETCH_ARGS: Tuple[str, ...] = ("url", "uri", "link", "website", "webpage", "address", "href")
READ_FETCH_VERBS: Tuple[str, ...] = ("browse", "get", "fetch", "read", "download", "view", "search",
                                     "list", "retrieve", "load", "open", "show", "lookup")
WRITE_VERBS: Tuple[str, ...] = ("post", "send", "share", "upload", "publish", "submit", "create",
                                "write", "invite", "transfer", "add", "grant", "give")


def _split_tokens(name) -> list:
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(name))
    return [t for t in re.split(r"[^a-z0-9]+", s.lower()) if t]


@dataclass(frozen=True)
class Lexicon:
    """Role vocabulary with the AgentDojo defaults of the paper.

    ``agentdyn_mode`` switches tool-name classification from prefix matching to token-set
    matching (for namespaced tools such as ``git_delete_repo``) and adds the principal hints
    to the target roles, exactly as the reference does for the AgentDyn suites.
    ``extprincipal`` is the paper's setting (on): a credential argument is a self/payload
    value, never an external-principal target, and credential INSTALL stays gated separately.
    """

    read_prefixes: Tuple[str, ...] = READ_PREFIXES
    write_prefixes: Tuple[str, ...] = WRITE_PREFIXES
    destructive_prefixes: Tuple[str, ...] = DESTRUCTIVE_PREFIXES
    destruct_intent: Tuple[str, ...] = DESTRUCT_INTENT
    grant_prefixes: Tuple[str, ...] = GRANT_PREFIXES
    target_arg_hints: FrozenSet[str] = TARGET_ARG_HINTS
    extra_target_hints: FrozenSet[str] = frozenset()
    principal_hints: FrozenSet[str] = PRINCIPAL_HINTS
    credential_hints: FrozenSet[str] = CREDENTIAL_HINTS
    credential_role: FrozenSet[str] = CREDENTIAL_ROLE
    principal_arg_hints: FrozenSet[str] = PRINCIPAL_ARG_HINTS
    agentdyn_id_fields: FrozenSet[str] = AGENTDYN_ID_FIELDS
    self_write_tools: FrozenSet[str] = SELF_WRITE_TOOLS
    self_write_recipient_args: FrozenSet[str] = SELF_WRITE_RECIPIENT_ARGS
    slack_msg_sinks: FrozenSet[str] = SLACK_MSG_SINKS
    fetch_args: Tuple[str, ...] = FETCH_ARGS
    read_fetch_verbs: Tuple[str, ...] = READ_FETCH_VERBS
    write_verbs: Tuple[str, ...] = WRITE_VERBS
    agentdyn_mode: bool = False
    extprincipal: bool = True
    id_agentdyn: bool = True

    # ---- construction helpers --------------------------------------------------------------
    @classmethod
    def for_agentdyn(cls, **overrides) -> "Lexicon":
        """The AgentDyn-suite settings (github / shopping / dailylife)."""
        kw = dict(agentdyn_mode=True, extra_target_hints=AGENTDYN_TARGET_HINTS)
        kw.update(overrides)
        return cls(**kw)

    def extend(self, **more) -> "Lexicon":
        """Return a copy with the given entries ADDED (never removed) to the named fields.

        ``Lexicon().extend(target_arg_hints={"payee"}, self_write_tools={"create_note"})``.
        Boolean fields are replaced.
        """
        kw = {}
        for f in dataclasses.fields(self):
            if f.name not in more:
                continue
            cur = getattr(self, f.name)
            new = more[f.name]
            if isinstance(cur, bool):
                kw[f.name] = bool(new)
            elif isinstance(cur, tuple):
                kw[f.name] = tuple(cur) + tuple(x for x in new if x not in cur)
            else:
                kw[f.name] = frozenset(cur) | frozenset(new)
        unknown = set(more) - {f.name for f in dataclasses.fields(self)}
        if unknown:
            raise TypeError("unknown lexicon fields: %s" % ", ".join(sorted(unknown)))
        return dataclasses.replace(self, **kw)

    # ---- tool-name classification (taint-gate module: tool_is_read_only / _is_destructive) ----
    def tool_is_read_only(self, tool_name: str) -> bool:
        name = str(tool_name).lower()
        if self.agentdyn_mode:
            _toks = name.split("_")
            _wv = {p.rstrip("_") for p in self.write_prefixes}
            _rv = {p.rstrip("_") for p in self.read_prefixes}
            if any(t in _wv for t in _toks):
                return False
            return any(t in _rv for t in _toks)
        if any(name.startswith(p) for p in self.write_prefixes):
            return False
        return any(name.startswith(p) for p in self.read_prefixes)

    def is_destructive(self, name: str) -> bool:
        n = str(name).lower()
        if self.agentdyn_mode:
            _verbs = {p.rstrip("_") for p in self.destructive_prefixes}
            return any(t in _verbs for t in n.split("_"))
        return any(n.startswith(p) for p in self.destructive_prefixes)

    def user_authorized_destruction(self, user_task: str) -> bool:
        t = str(user_task).lower()
        return any(not INTENT_NEGATED.search(t[:m.start()])
                   for w in self.destruct_intent
                   for m in re.finditer(r"\b" + re.escape(w) + INTENT_TAIL, t))

    def is_access_grant(self, name: str) -> bool:
        return any(str(name).lower().startswith(p) for p in self.grant_prefixes)

    def is_self_write_tool(self, name: str) -> bool:
        return str(name).lower() in self.self_write_tools

    def is_slack_msg_sink(self, name: str) -> bool:
        return str(name).lower() in self.slack_msg_sinks

    # ---- argument-name classification (taint-gate module: _is_target_arg and friends) ----------
    def arg_is_credential(self, name) -> bool:
        toks = _split_tokens(name)
        return str(name).lower() in self.credential_role or any(t in self.credential_role for t in toks)

    def is_credential_install(self, name) -> bool:
        n = str(name).lower()
        parts = n.split("_")
        if not (any(x in n for x in CRED_NOUNS) or "key" in parts):
            return False
        return any(v in parts for v in CRED_INSTALL_VERBS)

    @staticmethod
    def cred_install_authorized(user_task) -> bool:
        t = str(user_task).lower()
        return any(w in t for w in CRED_INSTALL_INTENT)

    def is_target_arg(self, name: str) -> bool:
        if self.extprincipal and self.arg_is_credential(name):
            return False   # a credential is a self/payload value, never an external-principal target
        _hints = self.target_arg_hints | self.extra_target_hints
        if self.agentdyn_mode:
            _hints = _hints | self.principal_hints
            if not self.extprincipal:
                _hints = _hints | self.credential_hints
        toks = _split_tokens(name)
        if any(t in FREE_TEXT_WORDS for t in toks):
            return False
        return str(name).lower() in _hints or any(t in _hints for t in toks)

    def is_principal_arg(self, name: str) -> bool:
        lname = str(name).lower()
        toks = _split_tokens(lname)
        return lname in self.principal_arg_hints or any(t in self.principal_arg_hints for t in toks)

    def agentdyn_id_field(self, fname) -> bool:
        return self.id_agentdyn and re.sub(r"\s+", " ", str(fname)).strip().lower() in self.agentdyn_id_fields

    def is_fetch_arg(self, name: str) -> bool:
        n = str(name).lower()
        return any(h in n for h in self.fetch_args)

    def is_read_fetch_url2(self, name, argname) -> bool:
        """Safe read-fetch exemption: browse/get/fetch/view/read of a URL brings data IN; a
        download WRITES to a destination and stays gated."""
        if not self.is_fetch_arg(argname):
            return False
        parts = str(name).lower().split("_")
        _writes = {p.rstrip("_") for p in self.write_prefixes}
        if any(w in parts for w in self.write_verbs) or "download" in parts or any(p in _writes for p in parts):
            return False
        return any(w in parts for w in tuple(v for v in self.read_fetch_verbs if v != "download"))

    def is_read_fetch_url(self, name, argname) -> bool:
        """The v1 read-fetch exemption (includes download); off in the paper's runs."""
        if not self.is_fetch_arg(argname):
            return False
        parts = str(name).lower().split("_")
        if any(w in parts for w in self.write_verbs):
            return False
        return any(w in parts for w in self.read_fetch_verbs)


DEFAULT_LEXICON = Lexicon()
