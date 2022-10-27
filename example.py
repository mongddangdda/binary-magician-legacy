import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from binaryninja.binaryview import BinaryViewType
from binaryninja.function import Function
from utils.runner import Runner
from utils.utils import get_all_files_from_path


def solution(bv: BinaryViewType) -> list[Function]:

    result = [] # spicious function list
    
    # your code here

    return result

if __name__ == '__main__':
    file_list = get_all_files_from_path('/path/of/binary')
    runner = Runner(solution, file_list)
    runner.run()
