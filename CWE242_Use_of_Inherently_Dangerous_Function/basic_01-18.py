import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from binaryninja import *
from utils.evaluation import get_all_files_from_path, get_answer, evaluate_result

def solution(bv: BinaryViewType) -> list:

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
    binary_path = '/Users/ch4rli3kop/binary-nomaj/Juliet_1.3/testcases/CWE242_Use_of_Inherently_Dangerous_Function/'
    files = get_all_files_from_path(binary_path)

    for file in files:
        bv = binaryview.BinaryViewType.get_view_of_file(file)
        result = solution(bv)
        answer = get_answer(bv)
        evaluate_result(result, answer)
        