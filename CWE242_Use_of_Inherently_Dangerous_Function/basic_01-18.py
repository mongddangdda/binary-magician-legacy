import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from binaryninja.binaryview import BinaryViewType
from binaryninja.function import Function
from utils.runner import Runner
from utils.utils import get_all_files_from_path


def solution(bv: BinaryViewType) -> list[Function]:

    result = [] # spicious function list

    targets = {
        'gets': [0],
        '_gets': [0]
    }

    for target in targets:
        target = bv.get_functions_by_name(target)
        if len(target) < 1:
            continue
        target = target[0]
        xrefs = bv.get_code_refs(target.start)
        for ref in xrefs:
            text = f'suspicous point : {ref.address:#x} at function {ref.function.start:#x}'
            #print(text)
            result.append(ref.function)
    
    return result

if __name__ == '__main__':
    binary_path = '/Users/ch4rli3kop/binary-nomaj/Juliet_amd64/testcases/CWE242_Use_of_Inherently_Dangerous_Function/'
    file_list = get_all_files_from_path(binary_path)

    runner = Runner(solution, file_list)
    runner.run()
    