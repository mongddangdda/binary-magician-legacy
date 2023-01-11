from utils.utils import *
from utils.path.path_finder import *
from binaryninja import *
from utils.runner import Runner
from utils.angr_manager import AngrManager
import logging

logging.basicConfig(filename='', format='%(levelname)s:%(message)s', level=logging.INFO)

# from CWE134_Uncontrolled_Format_String.format_string import source_targets, sink_targets, solution
from CWE190_Integer_Overflow.integer_overflow import make_sources_and_sinks, solution


def detect_suspicious(bv: BinaryView) -> list[Function]:
    result = []
    sources, sinks = make_sources_and_sinks(bv=bv)

    pf = PathFinder(bv=bv, sources=sources, sinks=sinks, option=PathGenOption.POSSIBLE_VALUE_UPDATE)
    paths = pf.generate_path()
    #pf.save_entire_graph('test_entire_graph.html')
    for path in paths:

        # feasible check
        # angr_manager = AngrManager(path=path)
        # if angr_manager.check_feasible():
        #     print(f'This Path are feasible!')

        # check user input
        if path.check_user_controllable():
            print(f'The user input affects sink!')
        
        #path.show_pathobject() # for debug, you can view all element of node and edge
        path.save_graph() # if name is None, filename is random
        path.save_bndb_file_by_path()
        vuln = solution(bv, path)
        if len(vuln) > 0:
            print(path.get_path())
            result.extend(vuln)
    return result


if __name__ == '__main__':


    #binary = 'D:\\Projects\\binary-nomaj\\C\\testcases\\CWE134_Uncontrolled_Format_String\\s01\\CWE134_Uncontrolled_Format_String__char_connect_socket_printf_45.out'
    binary = 'D:\\Projects\\binary-nomaj\\C\\testcases\\CWE190_Integer_Overflow\\s02\\CWE190_Integer_Overflow__int_fgets_add_54.out'
    #binary = 'D:\\Projects\\binary-nomaj\\C\\testcases\\CWE190_Integer_Overflow\\s02'
    
    #bv = binaryview.BinaryViewType.get_view_of_file(binary)
    
    # file_list = get_all_files_from_path(binary)
    file_list = get_matched_files_from_path(path=binary, reg='^((?!rand|max).)*$')
    runner = Runner(detect_suspicious, file_list)
    runner.run()