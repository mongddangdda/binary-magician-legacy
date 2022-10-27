import re
from binaryninja.binaryview import BinaryViewType
from binaryninja.function import Function
from binaryninja.demangle import *
from binaryninja.architecture import Architecture
from utils.utils import is_cpp_binary

class Runner:
    def __init__(self, solution, file_list=[]) -> None:
        self.solution = solution
        self.file_list = file_list
        self.files_good = dict()
        self.files_missed = dict()
        self.files_fp = dict() # false positive
        self.cpp = []
        self._check_args()
    
    def _check_args(self) -> None:
        if self.solution is None:
            print(f'run with solution function!')
            exit()
        if len(self.file_list) < 1:
            print(f'run with file list!')
            exit()

    def run(self) -> None:
        
        for file in self.file_list:
            print(f'{file} is running... ')
            bv = BinaryViewType.get_view_of_file(file)
            if is_cpp_binary(bv):
                self.cpp.append(file)
                continue

            result = self.solution(bv)
            answer = self.get_answer(bv)
            self.evaluation(file, result, answer)
        self.show_result()

    def evaluation(self, file: str, result: list[Function], answer: list[Function]):
        # evaluate results
        # TODO: make comparing result with the real bad function more clear (ex. calculate f1-score?)
        result.sort()
        answer.sort()
        #print(file)
        if result == answer:
            print(f'good!')
            self.files_good[file] = result
            return

        for func in answer:
            if func not in result:
                print(f'you cant detect the bad function at {func.start:#x}')
                if file not in self.files_missed:
                    self.files_missed[file] = [func]
                else:
                    self.files_missed[file].append(func)

        for func in result:
            if func not in answer:
                print(f'false positive at {func.start:#x}')
                if file not in self.files_fp:
                    self.files_fp[file] = [func]
                else:
                    self.files_fp[file].append(func)

    def get_answer(self, bv: BinaryViewType) -> list[Function]:
        # FIXME: this code work correctly only when binary has one vulnerability
        # C
        bad_functions = [func for func in bv.functions if re.match('_?CWE.*badSink', func.name)]
        # when call like 54b_badSink -> 54c_badSink -> 54d_badSink ... it return max badSink function
        if len(bad_functions) > 1:
            bad_functions = { func.name : func for func in bv.functions if re.match('_?CWE.*badSink', func.name)}
            bad_functions = [ bad_functions[max(bad_functions.keys())] ]

        if len(bad_functions) < 1:
            bad_functions = [func for func in bv.functions if re.match('_?CWE.*bad$', func.name)]
                
        '''
        # TODO: move to the new Binary class
        # TODO: identify C++ binary and whether it is gnu3 or ms
        # C++ gnu3
        if len(bad_functions) < 1:
            # when gnu3 (linux)
            for func in bv.functions:
                if func.name[:2] == '_Z':
                    # it may be mangled name
                    name = demangle_gnu3(bv.arch, func.name)[1]
                    func_name = get_qualified_name(name)
                    if re.match('_?CWE.*badSink', func_name):
                        bad_functions.append(func)
        if len(bad_functions) < 1:
            # when gnu3 (linux)
            for func in bv.functions:
                if func.name[:2] == '_Z':
                    # it may be mangled name
                    name = demangle_gnu3(bv.arch, func.name)[1]
                    func_name = get_qualified_name(name)
                    if re.match('_?CWE.*bad$', func_name):
                        bad_functions.append(func)
        # C++ ms
        if len(bad_functions) < 1:
            # when ms
            for func in bv.functions:
                if func.name[:2] == '_Z':
                    # it may be mangled name
                    name = demangle_ms(bv.arch, func.name)[1]
                    func_name = get_qualified_name(name)
                    if re.match('_?CWE.*badSink', func_name):
                        bad_functions.append(func)
        if len(bad_functions) < 1:
            # when ms
            for func in bv.functions:
                if func.name[:2] == '_Z':
                    # it may be mangled name
                    name = demangle_ms(bv.arch, func.name)[1]
                    func_name = get_qualified_name(name)
                    if re.match('_?CWE.*bad$', func_name):
                        bad_functions.append(func)
        '''

        return bad_functions

    def show_result(self) -> None:
        total = len(self.file_list) - len(self.cpp)
        good = len(self.files_good)
        missed = len(self.files_missed)
        fp = len(self.files_fp)
        print(f'cpp binaries : {len(self.cpp)}')
        print(f'result [File]: \ngood: {good}/{total} \tmissed: {missed}/{total} \tfalse positive: {fp}/{total}')

        good = sum([len(self.files_good[file]) for file in self.files_good])
        missed = sum([len(self.files_missed[file]) for file in self.files_missed])
        fp = sum([len(self.files_fp[file]) for file in self.files_fp])
        total = good + missed + fp
        print(f'result [Vulnerabilities]: \ngood: {good}/{total} \tmissed: {missed}/{total} \tfalse positive: {fp}/{total}')
