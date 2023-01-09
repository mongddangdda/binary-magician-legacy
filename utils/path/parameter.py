from dataclasses import dataclass, replace
from binaryninja import MediumLevelILVarSsa, MediumLevelILConstPtr, MediumLevelILConst, SSAVariable, PossibleValueSet

@dataclass
class Parameter:
    param: MediumLevelILVarSsa | MediumLevelILConstPtr | MediumLevelILConst # if the type of element of params is MLIL_VAR_SSA, ssavar is SSAVariable 
    ssavar: SSAVariable | None # if the element is constant, ssavar is None
    possible_value: PossibleValueSet