from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field
from pydantic import model_validator


class MessageType(str, Enum):
    TASK = "TASK"
    RESULT = "RESULT"
    ALERT = "ALERT"
    ERROR = "ERROR"
    HEARTBEAT = "HEARTBEAT"


class A2ATask(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class A2ATraceHop(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent: str
    ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    latency_ms: float | None = None


class A2ATrace(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hop_count: int = 0
    hops: list[A2ATraceHop] = Field(default_factory=list)

    def add_hop(self, agent: str, *, latency_ms: float | None = None) -> None:
        self.hops.append(A2ATraceHop(agent=agent, latency_ms=latency_ms))
        self.hop_count = len(self.hops)


class A2ASecurity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    nonce: str
    signature: str


class A2AEnvelope(BaseModel):
    """
    Strict A2A message envelope:
    - Unknown fields are rejected (prevents “storage channels” via extra JSON keys).
    """

    model_config = ConfigDict(extra="forbid")

    message_id: UUID = Field(default_factory=uuid4)
    case_id: str
    parent_id: UUID | None = None
    from_agent: str
    to_agent: str
    type: MessageType

    task: A2ATask | None = None
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None

    trace: A2ATrace = Field(default_factory=A2ATrace)
    security: A2ASecurity | None = None

    @model_validator(mode="after")
    def _validate_by_type(self) -> "A2AEnvelope":
        if self.type == MessageType.TASK:
            if self.task is None:
                raise ValueError("TASK requires task")
            if self.result is not None or self.error is not None:
                raise ValueError("TASK must not include result/error")
        elif self.type == MessageType.RESULT:
            if self.result is None:
                raise ValueError("RESULT requires result")
            if self.task is not None or self.error is not None:
                raise ValueError("RESULT must not include task/error")
        elif self.type == MessageType.ERROR:
            if self.error is None:
                raise ValueError("ERROR requires error")
            if self.task is not None or self.result is not None:
                raise ValueError("ERROR must not include task/result")
        return self

    def require_type(self, expected: Literal["TASK", "RESULT", "ALERT", "ERROR", "HEARTBEAT"]) -> None:
        if self.type.value != expected:
            raise ValueError(f"expected envelope type={expected}, got {self.type.value}")
