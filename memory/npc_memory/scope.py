"""Company-layer scoping for trust-layer memory.

Streams scope as company_id -> team_id -> agent_id, with a shared company
stream and a shared fleet stream alongside the per-agent streams:

  fleet                        (no scope; fleet-wide learnings)
  company:{company_id}         (shared company stream)
  team:{company_id}:{team}     (shared team stream)
  agent:{company}:{team}:{agent}  (one stream per agent)

Two credentials are checked on a write:

1. The API key (transport credential, least privilege): key_may_write
   passes only when the key sits at or above the stream in the tree. An
   agent-scoped key touches only its own agent stream; a team-scoped key
   reaches the team stream and every agent stream under it; an unscoped
   key reaches everything including the fleet stream.

2. The writer (registered agent identity): agent_may_write passes when the
   agent belongs to the stream's branch: its own agent stream, its team's
   stream, its company's stream, or the fleet stream.

Reads are wider: key_may_read passes when the key and the stream share a
branch in either direction (an agent reads its team and company streams),
and the fleet stream is readable by any authenticated key. Fleet writes
additionally need an issuer or admin API key.
"""
import re
from dataclasses import dataclass
from typing import Optional

MEMORY_TYPES = ("memory.assert", "memory.supersede", "memory.retract")
STREAM_KINDS = ("agent", "team", "company", "fleet")
FLEET_WRITE_ROLES = ("issuer", "admin")

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_RECORD_ID_RE = re.compile(r"^mem_[A-Za-z0-9_-]{8,64}$")
_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")


def valid_scope_id(value) -> bool:
    return isinstance(value, str) and bool(_ID_RE.match(value))


def valid_record_id(value) -> bool:
    return isinstance(value, str) and bool(_RECORD_ID_RE.match(value))


def valid_tag(value) -> bool:
    return isinstance(value, str) and bool(_TAG_RE.match(value))


@dataclass(frozen=True)
class Scope:
    """A place in the company -> team -> agent tree. None = no restriction."""
    company_id: Optional[str] = None
    team_id: Optional[str] = None
    agent_id: Optional[str] = None

    def validate(self) -> list:
        problems = []
        for name in ("company_id", "team_id", "agent_id"):
            v = getattr(self, name)
            if v is not None and not valid_scope_id(v):
                problems.append(f"{name} must match [A-Za-z0-9_-] (max 64)")
        if self.team_id and not self.company_id:
            problems.append("team_id requires company_id")
        # agent_id without team_id is a fleet-level agent; allowed.
        return problems


def stream_key(kind: str, company_id=None, team_id=None,
               agent_id=None) -> str:
    """Canonical stream identifier. Raises ValueError on bad dimensions."""
    if kind not in STREAM_KINDS:
        raise ValueError(f"stream kind must be one of {STREAM_KINDS}")
    if kind == "fleet":
        if company_id or team_id or agent_id:
            raise ValueError("fleet stream takes no scope dimensions")
        return "fleet"
    if not valid_scope_id(company_id or ""):
        raise ValueError("company/team/agent streams need a company_id")
    if kind == "company":
        if team_id or agent_id:
            raise ValueError("company stream takes no team/agent dimension")
        return f"company:{company_id}"
    if not valid_scope_id(team_id or ""):
        raise ValueError("team/agent streams need a valid team_id")
    if kind == "team":
        if agent_id:
            raise ValueError("team stream takes no agent dimension")
        return f"team:{company_id}:{team_id}"
    if not valid_scope_id(agent_id or ""):
        raise ValueError("agent streams need a valid agent_id")
    return f"agent:{company_id}:{team_id}:{agent_id}"


def _dims(company_id, team_id, stream_agent_id):
    return (("company_id", company_id), ("team_id", team_id),
            ("agent_id", stream_agent_id))


def key_may_read(key: Scope, kind: str, company_id=None, team_id=None,
                 stream_agent_id=None) -> bool:
    """A key reads a stream when both sit on the same branch (either order).

    An agent-scoped key reads its own stream plus its team, company, and
    the fleet stream. It never reads another company's streams.
    """
    for name, stream_dim in _dims(company_id, team_id, stream_agent_id):
        key_dim = getattr(key, name)
        if (key_dim is not None and stream_dim is not None
                and key_dim != stream_dim):
            return False
    return True


def key_may_write(key: Scope, kind: str, company_id=None, team_id=None,
                  stream_agent_id=None) -> bool:
    """A key writes a stream only when the key sits at or above the stream."""
    for name, stream_dim in _dims(company_id, team_id, stream_agent_id):
        key_dim = getattr(key, name)
        if key_dim is not None and key_dim != stream_dim:
            return False
    return True


def agent_may_write(agent_scope: Scope, kind: str, company_id=None,
                    team_id=None, stream_agent_id=None) -> bool:
    """A registered agent writes its own stream and shared streams above it.

    An agent in team T of company C writes: its agent stream, T's team
    stream, C's company stream. Any registered agent may contribute to the
    fleet stream; the fleet stream carries writer attribution (agent_id
    plus writer company/team), and the API additionally gates fleet writes
    on an issuer/admin key. Never another team, company, or agent.
    """
    if kind == "fleet":
        return True
    if agent_scope.company_id != company_id:
        return False
    if team_id is not None and agent_scope.team_id != team_id:
        return False
    if kind == "agent":
        return agent_scope.agent_id == stream_agent_id
    return True


def fleet_write_allowed(role: str) -> bool:
    return role in FLEET_WRITE_ROLES
