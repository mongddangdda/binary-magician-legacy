from binaryninja import Function, MediumLevelILCall, MediumLevelILVarSsa, MediumLevelILConst, MediumLevelILConstPtr, MediumLevelILOperation, SSAVariable, PossibleValueSet
from utils.path.parameter import Parameter
import logging
import pprint
from enum import Enum, auto

class PEdgeType(Enum):
    IS_CALL = auto()
    IS_CALL_RETURN = auto() # NOT IMPLEMENTED!
    IS_ARITHMETIC = auto()


class PEdge:
    def __init__(self, start: Function = None, end: Function = None, address: int = None, taint_args: list[int] = None) -> None:
        assert start is not None and address is not None
        self.type: PEdgeType
        self.start: Function = start
        self.end: Function = end
        self.address: int = address
        self.instr: MediumLevelILCall
        self.parameters: dict[str, Parameter] = dict()
        '''
            {
                'arg0': Parameters
                'arg1': Parameters
                ...
            }
        '''
        self.taint_args: list[int] = taint_args
        self.return_value = None # Not implemented

        # initialize empty attributes
        self.instr = self.start.get_llil_at(self.address).mlil
        assert self.instr is not None

        # initialize PEdge type
        if self.instr.operation is MediumLevelILOperation.MLIL_CALL:
            self.type = PEdgeType.IS_CALL
        elif self.instr.operation is MediumLevelILOperation.MLIL_SET_VAR:
            self.type = PEdgeType.IS_ARITHMETIC

        self.initialize_param()

    def __hash__(self) -> int:
        return hash(self.address)

    def __repr__(self) -> str:
        result = f'\n################  edge  ###############\n'
        result += f'Thid edge is {self.start} -> {self.end}\n'
        result += f'address: {self.address:#x}\n'
        result += f'instruction: {self.instr}\n'
        result += pprint.pformat(self.parameters) + '\n'
        result += f'taint_args: {self.taint_args}\n'
        result += f'#######################################\n'

        return result


    def initialize_param(self):
        # TODO: 전역변수일 때 확인해보기

        # call 일 때
        if self.type is PEdgeType.IS_CALL:
            for idx, parameter in enumerate(self.instr.ssa_form.params):
                if type(parameter) is MediumLevelILVarSsa:
                    possible_value = self.instr.ssa_form.get_ssa_var_possible_values(parameter.src)
                    param = Parameter(param=parameter, ssavar=parameter.src, possible_value=possible_value)
                    self.parameters[f'arg{idx}'] = param
                elif type(parameter) is MediumLevelILConst:
                    possible_value = PossibleValueSet.constant(parameter.constant)
                    param = Parameter(param=parameter, ssavar=None, possible_value=possible_value)
                    self.parameters[f'arg{idx}'] = param
                elif type(parameter) is MediumLevelILConstPtr:
                    possible_value = PossibleValueSet.constant_ptr(parameter.constant)
                    param = Parameter(param=parameter, ssavar=None, possible_value=possible_value)
                    self.parameters[f'arg{idx}'] = param
                else:
                    logging.error(f'New type of param appear! please check arg{idx} of {self.instr} at {self.address}')
                    raise NotImplemented
                logging.debug(f'arg{idx}: {param.param}, {param.ssavar}, {param.possible_value}')
        
        elif self.type is PEdgeType.IS_ARITHMETIC:
            # for integer overflow
            if self.instr.ssa_form.src.operation not in (MediumLevelILOperation.MLIL_ADD, MediumLevelILOperation.MLIL_SUB, MediumLevelILOperation.MLIL_MUL):
                return
            ssavar = self.instr.ssa_form.dest
            possible_value = self.instr.ssa_form.get_ssa_var_possible_values(ssavar)
            param = Parameter(param=self.instr.ssa_form, ssavar=ssavar, possible_value=possible_value)
            self.parameters[f'operand0'] = param

            for idx, operand in enumerate(self.instr.ssa_form.src.operands):
                if type(operand) is MediumLevelILVarSsa:
                    possible_value = self.instr.ssa_form.get_ssa_var_possible_values(operand.src)
                    param = Parameter(param=operand, ssavar=operand.src, possible_value=possible_value)
                    self.parameters[f'operand{idx+1}'] = param
                elif type(operand) is MediumLevelILConst:
                    possible_value = PossibleValueSet.constant(operand.constant)
                    param = Parameter(param=operand, ssavar=None, possible_value=possible_value)
                    self.parameters[f'operand{idx+1}'] = param
                elif type(operand) is MediumLevelILConstPtr:
                    possible_value = PossibleValueSet.constant_ptr(operand.constant)
                    param = Parameter(param=operand, ssavar=None, possible_value=possible_value)
                    self.parameters[f'operand{idx+1}'] = param
                else:
                    logging.error(f'New type of param appear! please check arg{idx} of {self.instr} at {self.address}')
                    raise NotImplemented
                logging.debug(f'operand{idx}: {param.param}, {param.ssavar}, {param.possible_value}')


    def update_possible_value(self):
        '''
        update the possible value set of arguments at end function
        '''
        for instr in self.end.mlil.ssa_form.basic_blocks[0]:
            if instr.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA and \
                type(instr.src) == MediumLevelILVarSsa:
                name: str = instr.src.src.var.name

                if name.startswith('arg'):
                    key = f'arg{int(name.split("arg")[1]) - 1}' # in binary ninja name rules, it start at arg1, but arg0 in this framwork.
                    var = instr.dest.var
                    possible_value: Parameter = self.parameters[key]
                    if type(possible_value) is PossibleValueSet:
                        self.end.set_user_var_value(var=var, def_addr=instr.address, value=possible_value.possible_value)

    def get_ssavars_to_taint(self) -> list[SSAVariable]:
        # taint 할 argument 중에서 ssavar 리턴하기
        # TODO: 전역변수는 어떻게 되는지 확인하기
        assert self.taint_args is not None
        ssavars = []
        for arg in self.taint_args:
            arg: int
            if self.type is PEdgeType.IS_CALL:
                key = f'arg{arg}'
                param: Parameter = self.parameters[key]
                if param.ssavar is not None:
                    ssavars.append(param.ssavar)
            elif self.type is PEdgeType.IS_ARITHMETIC:
                key = f'operand{arg}'
                param: Parameter = self.parameters[key]
                if param.ssavar is not None:
                    ssavars.append(param.ssavar)
                    
        return ssavars