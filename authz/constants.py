"""Constant values used in authz module."""
from dataclasses import dataclass

STATUS_ACTIVE = "ACTIVE"
STATUS_INACTIVE = "INACTIVE"
LIFECYCLE = "LC"


@dataclass
class Policy:
    policy_id: int
    name: str
    policy_type: str


class Policies:
    @staticmethod
    def by_id(policy_id):
        """Return policy object given its ID"""
        return next(
            attr
            for attr in dir(Policies)
            if getattr(getattr(Policies, attr), "policy_id", None) == policy_id
        )

    @staticmethod
    def by_name(name):
        """Returns policy object given its name"""
        return next(
            attr
            for attr in dir(Policies)
            if getattr(getattr(Policies, attr), "name", None) == name
        )

    UseForever = Policy(policy_id=1, name="Use Forever", policy_type=LIFECYCLE)
    UseUntil = Policy(policy_id=2, name="Use Until", policy_type=LIFECYCLE)
    UseOnceBefore = Policy(policy_id=3, name="Use Once Before", policy_type=LIFECYCLE)
