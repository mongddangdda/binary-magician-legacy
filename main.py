from utils.utils import *
from utils.path.path_finder import *
from binaryninja import *
from utils.runner import Runner
import logging
from utils.path.options import PFOption

logging.basicConfig(filename='', format='%(levelname)s:%(message)s', level=logging.INFO)

def main(args):

    if args.cwe == 'integer_overflow':
        from CWE190_Integer_Overflow.integer_overflow import make_sources_and_sinks, solution
    elif args.cwe == 'format_string':
        from CWE134_Uncontrolled_Format_String.format_string import make_sources_and_sinks, solution

    if args.file_regex:
        file_list = get_matched_files_from_path(args.file)
    else:
        file_list = get_all_files_from_path(args.file)

    options = parse_options(args.options)
   
    def detect_suspicious(bv: BinaryView) -> list[Function]:
        result = []
        sources, sinks = make_sources_and_sinks(bv=bv)

        pf = PathFinder(bv=bv, sources=sources, sinks=sinks, option=options)
        paths = pf.generate_path()

        for path in paths:
            print(path.get_path())
            if PFOption.CHECK_FEASIBLE in options:
                if not check_feasible(path=path):
                    continue
            
            # path.show_pathobject() # for debug, you can view all element of node and edge

            if PFOption.CHECK_USER_CONTROLLABLE:
                if not check_user_controllable(path=path):
                    continue
                
            vuln = solution(bv, path)
            if len(vuln) > 0:
                print(f'Find!')
                result.extend(vuln)
                #path.show_pathobject() # for debug, you can view all element of node and edge
                #path.save_graph() # if name is None, filename is random
                #path.save_bndb_file_by_path()

        return result

    runner = Runner(detect_suspicious, file_list)
    runner.run()



if __name__ == '__main__':

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--cwe', required=True, help='integer_overflow or format_string')
    parser.add_argument('--file', required=True, help='file or directory name')
    parser.add_argument('--file_regex', required=False, help='if you want to filter file name with regex, use this argument')
    parser.add_argument('--options', required=False, nargs='+', help='POSSIBLE_VALUE_UPDATE|CHECK_FEASIBLE|CHECK_USER_CONTROLLABLE')
    args = parser.parse_args()

    main(args)
