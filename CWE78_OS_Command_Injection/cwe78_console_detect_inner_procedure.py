import os
import sys
import logging

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from binaryninja import *
from binaryninja.binaryview import BinaryViewType
from binaryninja.function import Function
from utils.runner import Runner
from utils.utils import get_matched_files_from_path

import analyzers.config
from analyzers.mliltracer import *

def taint():
    pass

def solution(bv: BinaryViewType) -> list[Function]:

    result = [] # spicious function list

    # your code here
    targets_input = {
        'fgets': [0],
    }

    input_xrefs = list()
    for function in targets_input:
        target = bv.get_functions_by_name(function)
        target = target[0]
        xrefs = bv.get_code_refs(target.start)
        for ref in xrefs:
            input_xrefs.append(ref.function)

    targets_vuln = {
        'execlp': [3],
    }

    vuln_xrefs = list()
    for function in targets_vuln:
        target = bv.get_functions_by_name(function)
        target = target[0]
        xrefs = bv.get_code_refs(target.start)
        for ref in xrefs:
            vuln_xrefs.append(ref.function)

    co_exists = list(set(input_xrefs).intersection(vuln_xrefs))

    # TODO: How to taint analysis between input function and vuln function?
    if co_exists:
        result.append(taint())

    return co_exists

if __name__ == '__main__':
    binary_path = '/Users/kiddo/workspace/C/testcases/CWE78_OS_Command_Injection/s01'
    testcase_pattern = 'CWE78_OS_Command_Injection__char_console_execlp_*'
    file_list = get_matched_files_from_path(binary_path, testcase_pattern)

    runner = Runner(solution, file_list)
    runner.run()
