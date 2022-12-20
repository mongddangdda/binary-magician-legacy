import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from binaryninja import *
from binaryninja.binaryview import BinaryViewType
from binaryninja.function import Function
from utils.runner import Runner
from utils.utils import get_all_files_from_path
from utils.path_finder import *
from pprint import pprint

def solution(bv: BinaryViewType) -> list[Function]:

    # source = target(type='source', addr=0x14b2, function=bv.get_functions_containing(0x14b2)[0], ssavars=None, args=[2])
    # sink = target(type='source', addr=0x13f5, function=bv.get_functions_containing(0x13f5)[0], ssavars=None, args=[0])
    source = get_target_by_addr_args(bv=bv, type='source', addr=0x14b2, args=[2])
    sink = get_target_by_addr_args(bv=bv, type='sink', addr=0x13f5, args=[0])
    pf = PathFinder(bv)
    paths = pf.get_simple_path(source, sink)
    for path in paths:
        # print(path.graph.edges.data())
        # pprint(path)
        functions = pf.get_call_sites_by_path(path)
#        pprint(functions)
        for function, refs in functions.items():
            for ref, data in refs.items():
                pf.update_possibleValue(function, ref, data)
                # here your code

    #pf.save_path_to_image(graphs[0].graph, '.\\test4.png')

    return []

if __name__ == '__main__':
    binary_path = ('D:\\Projects\\binary-nomaj\\C\\testcases\\CWE190_Integer_Overflow\\s01\\CWE190_Integer_Overflow__char_fscanf_multiply_67.out')
    bv = binaryview.BinaryViewType.get_view_of_file(binary_path)
    solution(bv)
