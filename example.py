import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from binaryninja import *
from utils.evaluation import get_all_files_from_path, get_answer, evaluate_result

def solution(bv: BinaryViewType) -> list:

    result = [] # spicious function list
    
    # your code here

    return result

if __name__ == '__main__':
    binary_path = '/path/of/binary'
    files = get_all_files_from_path(binary_path)

    for file in files:
        bv = binaryview.BinaryViewType.get_view_of_file(file)
        result = solution(bv)
        answer = get_answer(bv)
        evaluate_result(result, answer)
        