'''

Runner Class:
    각 바이너리를 BinaryHalper 객체로 관리하며, 사용자의 solution 함수로 찾은 result와 실제 취약점인 answer를 비교하여
    통계를 내주는 역할을 수행함.

    주요작업
    - 각 바이너리를 BinaryHelper 객체로 매핑함
    - result와 answer를 가져와 비교함

'''


from pathlib import Path
import re
from binaryninja.binaryview import BinaryViewType
from binaryninja.function import Function
from binaryninja.demangle import *
from binaryninja.architecture import Architecture
from utils.utils import is_cpp_binary

from utils.binaryHelper import *

class Runner:
    def __init__(self, solution=None, file_list=[]) -> None:
        self.solution = solution
        self.file_list = file_list # TODO: {file: (result, answer)} 형태로
        self.files_good = dict()
        self.files_missed = dict()
        self.files_fp = dict() # false positive
        self.cpp = []
        self.options = 0 # c_only = 0, cpp_only = 1, all = 2
        self._check_args()
    
    def _check_args(self) -> None:
        if self.solution is None:
            print(f'run with solution function!')
            exit()
        if len(self.file_list) < 1:
            print(f'run with file list!')
            exit()

    def run(self, c_only = True, cpp_only = False, all = False ) -> None:
        if cpp_only:
            c_only = False
            self.options = 1
        elif all:
            self.options = 2

        file: Path
        for file in self.file_list:
            print(f'{file.name} is running... ')
            binary = CBinaryHelper(file)
            if binary.is_cpp and ( not c_only or all ):
                binary = CPPBinaryHelper(file)
                self.cpp.append(file)
            elif cpp_only:
                del binary
                continue
            
            result = binary.run(self.solution)
            answer = binary.get_answer()
            self.evaluation(file.name, result, answer)
            del binary
        self.show_result()

    def evaluation(self, file: str, result: list[Function], answer: list[Function]):
        RED = '\033[1;31;48m'
        END = '\033[1;37;0m'
        # evaluate results
        # TODO: make comparing result with the real bad function more clear (ex. calculate f1-score?)
        result.sort()
        answer.sort()
        #print(file)
        if result == answer:
            print(f'                                                                       good!')
            self.files_good[file] = result
            return

        for func in answer:
            if func not in result:
                print(f'{RED}                                                                       you cant detect the bad function at {func.start:#x}{END}')
                if file not in self.files_missed:
                    self.files_missed[file] = [func]
                else:
                    self.files_missed[file].append(func)
                return

        for func in result:
            if func not in answer:
                print(f'                                                                       false positive at {func.start:#x}')
                if file not in self.files_fp:
                    self.files_fp[file] = [func]
                else:
                    self.files_fp[file].append(func)

    def show_result(self) -> None:
        if self.options == 0:
            total = len(self.file_list) - len(self.cpp)
        elif self.options == 1:
            total = len(self.cpp)
        elif self.options == 2:
            total = len(self.file_list)

        good = len(self.files_good)
        missed = len(self.files_missed)
        fp = len(self.files_fp)
        print(f'c : {len(self.file_list)-len(self.cpp)}\tcpp : {len(self.cpp)}')
        print(f'result [File]: \ndetect: {good+fp}/{total} (good: {good}|false positive: {fp}) \tmissed: {missed}/{total}')

        # good = sum([len(self.files_good[file]) for file in self.files_good])
        # missed = sum([len(self.files_missed[file]) for file in self.files_missed])
        # fp = sum([len(self.files_fp[file]) for file in self.files_fp])
        # total = good + missed + fp
        # print(f'result [Vulnerabilities]: \ndetect: {good+fp}/{total}(good: {good}|false positive: {fp}) \tmissed: {missed}/{total}')
