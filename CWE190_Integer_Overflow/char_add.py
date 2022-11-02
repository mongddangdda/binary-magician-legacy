import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from binaryninja import *
from binaryninja.binaryview import BinaryViewType
from binaryninja.function import Function
from utils.runner import Runner
from utils.utils import get_all_files_from_path, get_matched_files_from_path

from z3 import *

def is_in_ranges(type):
    if type in ( RegisterValueType.SignedRangeValue, RegisterValueType.UnsignedRangeValue ):
        return True
    return False

def return_a_range(type: str):
    if type == 'char':
        return PossibleValueSet.signed_range_value([ValueRange(-128, 127, 1)]).ranges[0]
    elif type == 'short':
        return PossibleValueSet.signed_range_value([ValueRange(-0x1000, 0xffff, 1)]).ranges[0]
    elif type == 'int32_t':
        return PossibleValueSet.signed_range_value([ValueRange(-0x10000000, 0xffffffff, 1)]).ranges[0]
    elif type == 'int64_t':
        return PossibleValueSet.signed_range_value([ValueRange(-0x1000000000000000, 0xffffffffffffffff, 1)]).ranges[0]
    return None

def solution(bv: BinaryViewType) -> list[Function]:

    result = [] # spicious function list

    for func in bv.functions:
        for inst in func.mlil.ssa_form.instructions:
            if inst.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
                #print(inst)
                if inst.src.operation == MediumLevelILOperation.MLIL_ADD:
                    # FIXME: Range의 경우가 path에 영향을 받을 때, 현재 path를 구분하지 못하므로 false positive가 많음.
                    # TODO: a = 상수 + 상수 형태는 바이너리 닌자 LLIL -> MLIL 과정에서 a = value 형태로 최적화됨. 해당 경우 LLIL로 탐지해야 함.

                    # Add : SSaVariable + 상수
                    if type(inst.src.right) == MediumLevelILConst and type(inst.src.left) == MediumLevelILVarSsa:
                        # a = b + c(constant value)
                        a = inst.dest
                        b_value = inst.src.left.src
                        c = inst.src.right.constant

                        pv_b = inst.get_ssa_var_possible_values(b_value)
                        pv_a = return_a_range(a.type.get_string())
                        if pv_a is None:
                            continue

                        solver = Solver()
                        b = Int('b')                            
                        b_type = pv_b.type

                        # TODO: handle this types
                        if b_type in (RegisterValueType.ConstantPointerValue, RegisterValueType.ConstantValue, \
                            RegisterValueType.ExternalPointerValue, RegisterValueType.ImportedAddressValue, \
                                RegisterValueType.LookupTableValue, RegisterValueType.NotInSetOfValues, RegisterValueType.ReturnAddressValue, \
                                    RegisterValueType.StackFrameOffset):
                            continue

                        if b_type in ( RegisterValueType.SignedRangeValue, RegisterValueType.UnsignedRangeValue ):
                            pv_b = pv_b.ranges[0]
                            bi = Int('bi')
                            solver.add(b == pv_b.start + bi * pv_b.step)
                            solver.add(0 <= bi, bi <= (pv_b.end - pv_b.start)/pv_b.step)
                        elif b_type is RegisterValueType.InSetOfValues :
                            solver.add(Or([b == value for value in pv_b.values]))
                        elif b_type in ( RegisterValueType.EntryValue, RegisterValueType.UndeterminedValue ):
                            # FIXME: This is argument value
                            pv_b = return_a_range(b_value.type.get_string())
                            if pv_b is None:
                                continue
                            solver.add(pv_b.start <= b, b <= pv_b.end)

                        solver.push()
                        solver.add( b+c < pv_a.start )
                        if solver.check() == sat:
                            # print('integer overflow!')
                            result.append(func)
                        else:
                            solver.pop()
                            solver.add( b+c > pv_a.end )
                            if solver.check() == sat:
                                # print('integer overflow!')
                                result.append(func)


                    # Add : SSaVariable + SSaVariable
                    elif type(inst.src.right) == MediumLevelILVarSsa and type(inst.src.left) == MediumLevelILVarSsa:
                        # a = b + c
                        a = inst.dest
                        b_value = inst.src.left.src
                        c_value = inst.src.right.src
                        #print(a, b, c)
                        pv_b = inst.get_ssa_var_possible_values(b_value)
                        pv_c = inst.get_ssa_var_possible_values(c_value)

                        pv_a = return_a_range(a.type.get_string())
                        if pv_a is None:
                            continue

                        solver = Solver()
                        b = Int('b')
                        c = Int('c')
                        
                        b_type = pv_b.type
                        c_type = pv_c.type

                        # TODO: handle this types
                        if any( i in (RegisterValueType.ConstantPointerValue, RegisterValueType.ConstantValue, \
                            RegisterValueType.ExternalPointerValue, RegisterValueType.ImportedAddressValue, \
                                RegisterValueType.LookupTableValue, RegisterValueType.NotInSetOfValues, RegisterValueType.ReturnAddressValue, \
                                    RegisterValueType.StackFrameOffset) for i in (b_type, c_type)):
                            continue

                        if b_type in ( RegisterValueType.SignedRangeValue, RegisterValueType.UnsignedRangeValue ):
                            pv_b = pv_b.ranges[0]
                            bi = Int('bi')
                            solver.add(b == pv_b.start + bi * pv_b.step)
                            solver.add(0 <= bi, bi <= (pv_b.end - pv_b.start)/pv_b.step)
                        elif b_type in { RegisterValueType.InSetOfValues }:
                            solver.add(Or([b == value for value in pv_b.values]))
                        elif b_type in ( RegisterValueType.EntryValue, RegisterValueType.UndeterminedValue ):
                            # FIXME: This is argument value
                            pv_b = return_a_range(b_value.type.get_string())
                            if pv_b is None:
                                continue
                            solver.add(pv_b.start <= b, b <= pv_b.end)

                        if c_type in ( RegisterValueType.SignedRangeValue, RegisterValueType.UnsignedRangeValue ):
                            pv_c = pv_c.ranges[0]
                            ci = Int('ci')
                            solver.add(c == pv_c.start + ci * pv_c.step)
                            solver.add(0 <= ci, ci <= (pv_c.end - pv_c.start)/pv_c.step)
                        elif c_type is RegisterValueType.InSetOfValues:
                            solver.add(Or([c == value for value in pv_c.values]))
                        elif c_type in ( RegisterValueType.EntryValue, RegisterValueType.UndeterminedValue) :
                            # FIXME: This is argument value
                            pv_c = return_a_range(c_value.type.get_string())
                            if pv_c is None:
                                continue
                            solver.add(pv_c.start <= c, c <= pv_c.end)

                        solver.push()
                        solver.add( b+c < pv_a.start )
                        if solver.check() == sat:
                            # print('integer overflow!')
                            result.append(func)
                        else:
                            solver.pop()
                            solver.add( b+c > pv_a.end )
                            if solver.check() == sat:
                                # print('integer overflow!')
                                result.append(func)
                                
                # 곱셈 연산
                if inst.src.operation == MediumLevelILOperation.MLIL_MUL:
                    # FIXME: Range의 경우가 path에 영향을 받을 때, 현재 path를 구분하지 못하므로 false positive가 많음.
                    # TODO: a = 상수 + 상수 형태는 바이너리 닌자 LLIL -> MLIL 과정에서 a = value 형태로 최적화됨. 해당 경우 LLIL로 탐지해야 함.

                    # SSAVariable * 상수
                    if type(inst.src.right) == MediumLevelILConst and type(inst.src.left) == MediumLevelILVarSsa:
                        print(f'{func.start:#x}', inst)
                        # a = b + c(constant value)
                        a = inst.dest
                        b_value = inst.src.left.src
                        c = inst.src.right.constant

                        pv_b = inst.get_ssa_var_possible_values(b_value)                            
                        pv_a = return_a_range(a.type.get_string())

                        if pv_a is None:
                            continue

                        solver = Solver()
                        b = Int('b')                            
                        b_type = pv_b.type

                        # TODO: handle this types
                        if b_type in (RegisterValueType.ConstantPointerValue, RegisterValueType.ConstantValue, \
                            RegisterValueType.ExternalPointerValue, RegisterValueType.ImportedAddressValue, \
                                RegisterValueType.LookupTableValue, RegisterValueType.NotInSetOfValues, RegisterValueType.ReturnAddressValue, \
                                    RegisterValueType.StackFrameOffset):
                            continue

                        if b_type in ( RegisterValueType.SignedRangeValue, RegisterValueType.UnsignedRangeValue ):
                            pv_b = pv_b.ranges[0]
                            bi = Int('bi')
                            solver.add(b == pv_b.start + bi * pv_b.step)
                            solver.add(0 <= bi, bi <= (pv_b.end - pv_b.start)/pv_b.step)
                        elif b_type is RegisterValueType.InSetOfValues:
                            solver.add(Or([b == value for value in pv_b.values]))
                        elif b_type in ( RegisterValueType.EntryValue, RegisterValueType.UndeterminedValue ) :
                            # FIXME: This is argument value
                            pv_b = return_a_range(b_value.type.get_string())
                            if pv_b is None:
                                continue
                            solver.add(pv_b.start <= b, b <= pv_b.end)

                        solver.push()
                        solver.add( b*c < pv_a.start )
                        if solver.check() == sat:
                            # print('integer overflow!')
                            result.append(func)
                        else:
                            solver.pop()
                            solver.add( b*c > pv_a.end )
                            if solver.check() == sat:
                                # print('integer overflow!')
                                result.append(func)

                    # Multiply SSAVariable * SSaVariable
                    elif type(inst.src.right) == MediumLevelILVarSsa and type(inst.src.left) == MediumLevelILVarSsa:
                        # print(f'{func.start:#x}', inst)
                        # a = b + c
                        a = inst.dest
                        b_value = inst.src.left.src
                        c_value = inst.src.right.src
                        #print(a, b, c)
                        pv_a = inst.get_ssa_var_possible_values(a)
                        pv_b = inst.get_ssa_var_possible_values(b_value)
                        pv_c = inst.get_ssa_var_possible_values(c_value)

                        pv_a = return_a_range(a.type.get_string())
                        if pv_a is None:
                            continue

                        solver = Solver()
                        b = Int('b')
                        c = Int('c')
                        
                        b_type = pv_b.type
                        c_type = pv_c.type

                        # TODO: handle this types
                        if any( i in (RegisterValueType.ConstantPointerValue, RegisterValueType.ConstantValue, \
                            RegisterValueType.ExternalPointerValue, RegisterValueType.ImportedAddressValue, \
                                RegisterValueType.LookupTableValue, RegisterValueType.NotInSetOfValues, RegisterValueType.ReturnAddressValue, \
                                    RegisterValueType.StackFrameOffset, RegisterValueType.UndeterminedValue) for i in (b_type, c_type)):
                            continue

                        if b_type in ( RegisterValueType.SignedRangeValue, RegisterValueType.UnsignedRangeValue ):
                            pv_b = pv_b.ranges[0]
                            bi = Int('bi')
                            solver.add(b == pv_b.start + bi * pv_b.step)
                            solver.add(0 <= bi, bi <= (pv_b.end - pv_b.start)/pv_b.step)
                        elif b_type is RegisterValueType.InSetOfValues :
                            solver.add(Or([b == value for value in pv_b.values]))
                        elif b_type is ( RegisterValueType.EntryValue, RegisterValueType.UndeterminedValue ) :
                            # FIXME: This is argument value
                            pv_b = return_a_range(b_value.type.get_string())
                            if pv_b is None:
                                continue
                            solver.add(pv_b.start <= b, b <= pv_b.end)

                        if c_type in ( RegisterValueType.SignedRangeValue, RegisterValueType.UnsignedRangeValue ):
                            pv_c = pv_c.ranges[0]
                            ci = Int('ci')
                            solver.add(c == pv_c.start + ci * pv_c.step)
                            solver.add(0 <= ci, ci <= (pv_c.end - pv_c.start)/pv_c.step)
                        elif c_type is RegisterValueType.InSetOfValues :
                            solver.add(Or([c == value for value in pv_c.values]))
                        elif c_type in ( RegisterValueType.EntryValue, RegisterValueType.UndeterminedValue ) :
                            # FIXME: This is argument value
                            pv_c = return_a_range(c_value.type.get_string())
                            if pv_c is None:
                                continue
                            solver.add(pv_c.start <= c, c <= pv_c.end)

                        # check integer overflow
                        solver.push()
                        solver.add( b*c < pv_a.start )
                        if solver.check() == sat:
                            # print('integer overflow!')
                            result.append(func)
                        else:
                            solver.pop()
                            solver.add( b*c > pv_a.end )
                            if solver.check() == sat:
                                # print('integer overflow!')
                                result.append(func)
                                
    return result

if __name__ == '__main__':
    binary_path = '/Users/ch4rli3kop/binary-nomaj/integer_overflow_workspace/'
    file_list = get_all_files_from_path(binary_path, 1)
    #binary_path = '/Users/ch4rli3kop/binary-nomaj/Juliet_amd64/testcases/CWE190_Integer_Overflow/'
    #file_list = get_matched_files_from_path(binary_path, ".*__char_.*_multiply.*out")
    #file_list = get_matched_files_from_path(binary_path, ".*__int.*_multiply.*out")
    #file_list = get_matched_files_from_path(binary_path, ".*_multiply.*out")
    runner = Runner(solution, file_list)
    runner.run()
