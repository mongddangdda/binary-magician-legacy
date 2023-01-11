from utils.path.path_generator import *
from binaryninja import *
from z3 import *

source_targets = {
    '__isoc99_fscanf': [2], # 000011b0  int32_t __isoc99_fscanf(FILE* stream, char const* format, ...)
    'recv': [1]
}

# for sink_targets, use utils.make_arithmetic_targets()
def make_sources_and_sinks(bv: BinaryView):
    from utils.utils import make_targets, make_arithmetic_targets

    sources: list[PEdge] = make_targets(bv=bv, targets=source_targets)
    sinks: list[PEdge] = make_arithmetic_targets(bv)

    return sources, sinks

def is_in_ranges(type):
    return type in ( RegisterValueType.SignedRangeValue, RegisterValueType.UnsignedRangeValue )
        
def return_a_range(type: str):
    type_mapping = {
        'char': (-128, 127),
        'short': (-0x1000, 0xffff),
        'int16_t': (-0x1000, 0xffff),
        'int32_t': (-0x10000000, 0xffffffff),
        'int64_t': (-0x1000000000000000, 0xffffffffffffffff)
    }
    if type in type_mapping:
        return PossibleValueSet.signed_range_value([ValueRange(*type_mapping[type], 1)])
    raise

def check_type(left: MediumLevelILVarSsa, right : MediumLevelILVarSsa|MediumLevelILConst):
    pass

def solution(bv: BinaryView, path: PathObject):
    result: list[Function] = []

    # 사용자 input이 sink에 도달하는지 체크하기

    # interger overflow가 발생하는지
    sink: PEdge = path.sink
    instr = sink.instr.ssa_form
    
    if not isinstance(instr, MediumLevelILSetVarSsa):
        raise

    if not instr.src.operation in (MediumLevelILOperation.MLIL_ADD, MediumLevelILOperation.MLIL_MUL):
        raise

    left: MediumLevelILVarSsa = instr.src.left
    right: MediumLevelILVarSsa|MediumLevelILConst = instr.src.right

    if not (isinstance(left, MediumLevelILVarSsa) and ( isinstance(right, MediumLevelILVarSsa) or isinstance(right, MediumLevelILConst)) ):
        raise

    solver = Solver()

    # make a
    ssavar_a: SSAVariable = instr.dest
    pv_a: PossibleValueSet = return_a_range(ssavar_a.type.get_string())

    # make b
    # ssavar_b: SSAVariable = left.src
    ssavar_b: SSAVariable = sink.parameters['operand1'].ssavar
    # pv_b: PossibleValueSet = instr.get_ssa_var_possible_values(ssavar_b)
    pv_b: PossibleValueSet = sink.parameters['operand1'].possible_value
    if pv_b.type in ( RegisterValueType.EntryValue, RegisterValueType.UndeterminedValue ):
        pv_b = return_a_range(ssavar_b.type.get_string())
    b = Int('b')

    # make c
    if isinstance(right, MediumLevelILVarSsa):
        # ssavar_c: SSAVariable = right.src
        ssavar_c: SSAVariable = sink.parameters['operand2'].ssavar
        # pv_c: PossibleValueSet = instr.get_ssa_var_possible_values(ssavar_c)
        pv_c: PossibleValueSet = sink.parameters['operand2'].possible_value
        if pv_c.type in ( RegisterValueType.EntryValue, RegisterValueType.UndeterminedValue ):
            pv_c = return_a_range(ssavar_c.type.get_string())
        c = Int('c')
    elif isinstance(right, MediumLevelILConst):
        # pv_c: PossibleValueSet = PossibleValueSet.constant(right.constant)
        pv_c: PossibleValueSet = sink.parameters['operand2'].possible_value
        # c = right.constant
        c = pv_c.constant


    # TODO: handle this types
    if pv_b.type in (RegisterValueType.ConstantPointerValue, RegisterValueType.ConstantValue, \
                RegisterValueType.ExternalPointerValue, RegisterValueType.ImportedAddressValue, \
                    RegisterValueType.LookupTableValue, RegisterValueType.ReturnAddressValue, \
                        RegisterValueType.StackFrameOffset):
        return []
    
    def _make_operand_constraints(pv: PossibleValueSet, x: ArithRef, prefix:str):
        if pv.type in (RegisterValueType.SignedRangeValue, RegisterValueType.UnsignedRangeValue ):
            pv: ValueRange = pv.ranges[0]
            idx = Int(prefix)
            return x == pv.start + idx * pv.step, 0 <= idx, idx <= (pv.end - pv.start)/pv.step
        elif pv.type is RegisterValueType.InSetOfValues:
            return Or([x == value for value in pv.values])
        elif pv.type is RegisterValueType.NotInSetOfValues:
            return Or([x != value for value in pv.values])
        else:
            raise


    if isinstance(left, MediumLevelILVarSsa) and isinstance(right, MediumLevelILConst):
        # A = B(SSAVariable) operation C(constant)
        b_constraints = _make_operand_constraints(pv_b, b, 'bi')
        solver.add(b_constraints)

    elif isinstance(left, MediumLevelILVarSsa) and isinstance(right, MediumLevelILVarSsa):
        # A = B(SSAVariable) operation C(SSAVariable)
        c_constraints = _make_operand_constraints(pv_c, c, 'ci')
        b_constraints = _make_operand_constraints(pv_b, b, 'bi')

        solver.add(b_constraints)
        solver.add(c_constraints)
    else:
        raise

    solver.push()
    if instr.src.operation is MediumLevelILOperation.MLIL_ADD:
        solver.add( b+c < pv_a.ranges[0].start )
        if solver.check() == sat:
            logging.warning(f'Find Integer Overflow Bug!')
            result.append(sink.start)
        else:
            solver.pop()
            solver.add( b+c > pv_a.ranges[0].end )
            if solver.check() == sat:
                logging.warning(f'Find Integer Overflow Bug!')
                result.append(sink.start)

    elif instr.src.operation is MediumLevelILOperation.MLIL_MUL:
        solver.add( b*c < pv_a.ranges[0].start )
        if solver.check() == sat:
            logging.warning(f'Find Integer Overflow Bug!')
            result.append(sink.start)
        else:
            solver.pop()
            solver.add( b*c > pv_a.ranges[0].end )
            if solver.check() == sat:
                logging.warning(f'Find Integer Overflow Bug!')
                result.append(sink.start)
    return result