from utils.utils import *
from utils.path.path_finder import *
from pprint import pprint
from binaryninja import *
import logging

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)

def solution(bv):
    
    source_targets = {
        '__isoc99_fscanf': [2] # 000011b0  int32_t __isoc99_fscanf(FILE* stream, char const* format, ...)
    }

    sink_targets = {
        'printHexCharLine': [0], # 00001755  int64_t printHexCharLine(char arg1)
        'memcpy': [0, 1, 2]
    }

    def make_targets(bv: BinaryView, targets: dict[str, list[int]]) -> list[PFEdge]:
        result = []
        for func_name, taint_args in targets.items():
            functions = bv.get_functions_by_name(func_name)
            if len(functions) < 1:
                continue
            xrefs = bv.get_code_refs(functions[0].start)
            for ref in xrefs:
                ref: ReferenceSource
                result.append( PFEdge(start=ref.function, address=ref.address, taint_args=taint_args) )
        return result

    sources = make_targets(bv, source_targets)
    sinks = make_targets(bv, sink_targets)

    pf = PathFinder(bv=bv, sources=sources, sinks=sinks, option=PathGenOption.POSSIBLE_VALUE_UPDATE)
    paths = pf.generate_path()
    for path in paths:
        path.show_pathobject() # for debug
        path.save_graph() # if name is None, filename is random
        pprint(path.source)
        pprint(path.sink)

        for key, node in path.nodes.items():
            key: Function
            node: PFNode
            #print(node.tainted_vars_from_sink)
            #print(node.tainted_vars_from_source)

    return []

if __name__ == '__main__':

    binary_path = 'D:\\Projects\\binary-nomaj\\C\\testcases\\CWE190_Integer_Overflow\\s01\\CWE190_Integer_Overflow__char_fscanf_multiply_67.out'
    #binary_path = 'D:\\Projects\\binary-nomaj\\binja-snippets\\fileaccess.cgi'
    bv = binaryview.BinaryViewType.get_view_of_file(binary_path)
    solution(bv)
