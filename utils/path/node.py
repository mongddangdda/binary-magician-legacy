from binaryninja import Function, SSAVariable, MediumLevelILCall, MediumLevelILVarSsa, MediumLevelILConstPtr, PossibleValueSet, MediumLevelILConst, MediumLevelILOperation
from utils.path.parameter import Parameter
from utils.path.edge import PEdge


class PNode:
    def __init__(self, function = None) -> None:
        assert function is not None

        self.function: Function = function
        self.prev: PNode = None
        self.next: PNode = None
        self.prev_at: PEdge = None
        self.next_at: PEdge = None
        self.tainted_vars_from_source: list[SSAVariable] = []
        self.tainted_vars_from_sink: list[SSAVariable] = []
    

    def __hash__(self) -> int:
        return hash(self.function)

    def __repr__(self) -> str:
        result = f'\n##############  node  #################\n'
        result += f'\nThis node is {self.function}\n'
        result += f'prev: {self.prev.function if self.prev is not None else None}\nnext: {self.next.function if self.next is not None else None}\n'
        if self.prev_at is not None:
            result += f'prev_at: {self.prev_at.start} -> \n'
        else:
            result += f'prev_at: None\n'
        if self.next_at is not None:
            result += f'next_at: -> {self.next_at.end}\n'
        else:
            result += f'next_at: None\n'
        
        result += f'tainted_from_source: {self.tainted_vars_from_source}\ntainted_from_sink: {self.tainted_vars_from_sink}\n'
        result += f'#######################################\n'
        return result