import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from binaryninja import *
from binaryninja.binaryview import BinaryViewType
from binaryninja.function import Function
from utils.runner import Runner
from utils.utils import get_all_files_from_path


def solution(bv: BinaryViewType) -> list[Function]:

    result = [] # spicious function list

    for func in bv.functions:
        for inst in func.mlil.ssa_form.instructions:
            if inst.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
                #print(inst)
                if inst.src.operation == MediumLevelILOperation.MLIL_ADD:

                    # FIXME: 우항이 상수일 때 추가

                    if type(inst.src.right) == binaryninja.mediumlevelil.MediumLevelILVarSsa:
                        # a = b + c
                        a = inst.dest
                        b = inst.src.left.src
                        c = inst.src.right.src
                        #print(a, b, c)
                        a_range = inst.get_ssa_var_possible_values(a)
                        b_range = inst.get_ssa_var_possible_values(b)
                        c_range = inst.get_ssa_var_possible_values(c)

                        if a.var.type.get_string() == 'char':
                            a_range = a_range.signed_range_value([ValueRange(-128, 127, 1)])
                            # print(f'{func.start:#x}', inst, a_range, b_range, c_range)
                            try:
                                # FIXME: sometimes it can be RegisterValueType.InSetOfValues type
                                if a_range.ranges[0].end < b_range.ranges[0].end + c_range.ranges[0].end:
                                    #print('integer overflow!')
                                    result.append(func)
                            except:
                                pass
    return result

if __name__ == '__main__':
    binary_path = '/Users/ch4rli3kop/binary-nomaj/integer_overflow_workspace'
    file_list = get_all_files_from_path(binary_path)

    runner = Runner(solution, file_list)
    runner.run()
