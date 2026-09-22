from enum import Enum

from pydantic import BaseModel, Field


class RelationshipType(str, Enum):
    EXPOSED_TO = "exposed_to"
    CAN_ACCESS = "can_access"
    CAN_READ = "can_read"
    CAN_WRITE = "can_write"
    ASSUMES = "assumes"
    TRUSTS = "trusts"
    CONNECTED_TO = "connected_to"
    MEMBER_OF = "member_of"


class Relationship(BaseModel):
    source: str
    target: str
    relationship_type: RelationshipType

    permissions: list[str] = Field(default_factory=list)

    evidence: str | None = None
