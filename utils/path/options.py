from enum import Flag, auto

class PFOption(Flag):
    DEFAULT = auto()
    POSSIBLE_VALUE_UPDATE = auto()
    CHECK_FEASIBLE = auto()
    CHECK_USER_CONTROLLABLE = auto()