'''

1. CBinaryHelper Class
    각 C 바이너리를 관리하는 클래스로, 하나의 객체당 하나의 바이너리와 관련된 모든 작업을 수행하는 역할.
    
    주요 작업
    - 바이너리 아키텍쳐 구분
    - answer(real bad function) 식별
        - bad(badSource, badSink) path를 리턴
    - solution 적용
    - result(good, false positive, not detect) 리턴

2. CPPBinaryHelper Class
    각 C++ 바이너리를 관리하는 클래스로, 하나의 객체당 하나의 바이너리와 관련된 모든 작업을 수행하는 역할.
    CBinaryHelper를 상속하며, C++ 바이너리의 경우 function name이 mangle 되어 있으므로, demangle 하는 과정을 추가로 수행

'''
from pathlib import Path
from binaryninja import *
from utils.utils import is_cpp_binary

class CBinaryHelper:

    def __init__(self, file: Path = None) -> None:
        assert file is not None
        
        self.bv: BinaryView = BinaryViewType.get_view_of_file(file.absolute())
        self.platform: str = self.bv.platform.name
        self.is_cpp: bool = is_cpp_binary(self.bv)

    def run(self, solution = None):
        assert solution is not None
        return solution(self.bv)

    def get_answer(self) -> list[Function]:
        # FIXME: this code work correctly only when binary has one vulnerability
        bad_functions = [func for func in self.bv.functions if re.match('_?CWE.*badSink', func.name)]

        # when call like 54b_badSink -> 54c_badSink -> 54d_badSink ... it return max badSink function
        if len(bad_functions) > 1:
            bad_functions = { func.name : func for func in self.bv.functions if re.match('_?CWE.*badSink', func.name)}
            bad_functions = [ bad_functions[max(bad_functions.keys())] ]

        # some binary has just "badSink" function
        if len(bad_functions) < 1:
            bad_functions = [func for func in self.bv.functions if re.match('badSink', func.name)]

        if len(bad_functions) < 1:
            bad_functions = [func for func in self.bv.functions if re.match('_?CWE.*bad$', func.name)]
        
        return bad_functions

class CPPBinaryHelper(CBinaryHelper):
    def __init__(self, file: Path) -> None:
        super().__init__(file=file)

    def get_answer(self) -> list[Function]:
        # FIXME: this code work correctly only when binary has one vulnerability
        bad_functions = [func for func in self.bv.functions if re.match('_?CWE.*badSink', self.demangle_function(func))]

        # when call like 54b_badSink -> 54c_badSink -> 54d_badSink ... it return max badSink function
        if len(bad_functions) > 1:
            bad_functions = { self.demangle_function(func) : func for func in self.bv.functions if re.match('_?CWE.*badSink', self.demangle_function(func))}
            bad_functions = [ bad_functions[max(bad_functions.keys())] ]

        # some binary has just "badSink" function
        if len(bad_functions) < 1:
            bad_functions = [func for func in self.bv.functions if re.match('badSink', self.demangle_function(func))]

        if len(bad_functions) < 1:
            bad_functions = [func for func in self.bv.functions if re.match('_?CWE.*bad$', self.demangle_function(func))]
        
        return bad_functions

    def demangle_function(self, func: Function) -> str:
        if func.name[:2] == '_Z':
            if self.platform.split('-')[0] == 'linux':
                name = demangle_gnu3(self.bv.arch, func.name)[1]
            elif self.platform.split('-')[0] == 'windows':
                name = demangle_ms(self.bv.arch, func.name)[1]
            func_name = get_qualified_name(name)
            return func_name
        else:
            return func.name
