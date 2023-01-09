from utils.utils import *
from utils.path.path_finder import *
from binaryninja import *
import logging

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)


if __name__ == '__main__':

    binary_path = 'D:\\Projects\\binary-nomaj\\C\\testcases\\CWE190_Integer_Overflow\\s01\\CWE190_Integer_Overflow__char_fscanf_multiply_67.out'
    binary = 'CWE134_Uncontrolled_Format_String__char_connect_socket_fprintf_01.out'
    bv = binaryview.BinaryViewType.get_view_of_file(binary)
    
    source_targets = {
        '__isoc99_fscanf': [2], # 000011b0  int32_t __isoc99_fscanf(FILE* stream, char const* format, ...)
        'recv': [1]
    }

    sink_targets = {
        'printHexCharLine': [0], # 00001755  int64_t printHexCharLine(char arg1)
        'memcpy': [0, 1, 2],
        'fprintf': [1]
    }

    sources = make_targets(bv, source_targets)
    sinks = make_targets(bv, sink_targets)

    pf = PathFinder(bv=bv, sources=sources, sinks=sinks, option=PathGenOption.POSSIBLE_VALUE_UPDATE)
    paths = pf.generate_path()

    for path in paths:
        path.show_pathobject() # for debug, you can view all element of node and edge
        #path.save_graph() # if name is None, filename is random
        #path.save_bndb_file_by_path()
        #from CWE190_Integer_Overflow.integer_overflow import solution
        #solution(bv, path)
