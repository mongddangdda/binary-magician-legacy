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

    TODO: run 과정에서 answer 구하게하기
    

'''
from pathlib import Path
from binaryninja import *
from utils.utils import is_cpp_binary
import networkx as nx


class CBinaryHelper():

    def __init__(self, bv: BinaryView = None) -> None:
        assert bv is not None

        self.bv = bv
        self.platform: str = self.bv.platform.name
        self.bad_function = []
        self.bad_function_path = nx.DiGraph() # not using now

    def run(self, solution = None):
        assert solution is not None

        self.result = solution(self.bv)
        self._find_answer()
        self._find_answer_function_path()

    # @property
    # def result(self):
    #     return self.result

    @property
    def answer(self) -> list[Function]:
        return self.bad_function
    
    @property
    def answer_path(self) -> nx.DiGraph:
        return self.bad_function_path

    def _find_answer(self):
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
        self.bad_function = bad_functions

    def _find_answer_function_path(self):
        bad_function = [func for func in self.bv.functions if re.match('_?CWE.*bad$', func.name)]
        if len(bad_function) < 1:
            raise
        bad_function = bad_function[0]
        self.bad_function_path.add_node(bad_function.name)

        # badSink
        bad = bad_function
        while True:
            prev = bad.name
            bad = [func for func in bad.callees if re.match('.*bad.*Sink', func.name)]
            if len(bad) < 1:
                break
            bad = bad[0]
            self.bad_function_path.add_node(bad.name)
            self.bad_function_path.add_edge(prev, bad.name)

        # badSource
        bad = bad_function
        while True:
            prev = bad.name
            bad = [func for func in bad.callees if re.match('.*bad.*Source', func.name)]
            if len(bad) < 1:
                break
            bad = bad[0]
            self.bad_function_path.add_node(bad.name)
            self.bad_function_path.add_edge(prev, bad.name) 

class CPPBinaryHelper(CBinaryHelper):
    def __init__(self, bv: BinaryView) -> None:
        super().__init__(bv)

    def demangle_func_name(self, func: str) -> str:
        if func[:2] == '_Z':
            if self.platform.split('-')[0] == 'linux':
                name = demangle_gnu3(self.bv.arch, func)[1]
            elif self.platform.split('-')[0] == 'windows':
                name = demangle_ms(self.bv.arch, func)[1]
            func_name = get_qualified_name(name)
            return func_name
        else:
            return func

    def _find_answer(self):
        # FIXME: this code work correctly only when binary has one vulnerability
        bad_functions = [func for func in self.bv.functions if re.match('_?CWE.*badSink', self.demangle_func_name(func.name))]

        # when call like 54b_badSink -> 54c_badSink -> 54d_badSink ... it return max badSink function
        if len(bad_functions) > 1:
            bad_functions = { self.demangle_func_name(func.name) : func for func in self.bv.functions if re.match('_?CWE.*badSink', self.demangle_func_name(func.name))}
            bad_functions = [ bad_functions[max(bad_functions.keys())] ]

        # some binary has just "badSink" function
        if len(bad_functions) < 1:
            bad_functions = [func for func in self.bv.functions if re.match('badSink', self.demangle_func_name(func.name))]

        if len(bad_functions) < 1:
            bad_functions = [func for func in self.bv.functions if re.match('_?CWE.*bad$', self.demangle_func_name(func.name))]
        
        self.bad_function = bad_functions

    def _find_answer_function_path(self):
        bad_function = [func for func in self.bv.functions if re.match('_?CWE.*bad$', self.demangle_func_name(func.name))]
        if len(bad_function) < 1:
            raise
        bad_function = bad_function[0]
        self.bad_function_path.add_node(bad_function.name)

        # badSink
        bad = bad_function
        while True:
            prev = bad.name
            bad = [func for func in bad.callees if re.match('.*bad.*Sink', self.demangle_func_name(func.name))]
            if len(bad) < 1:
                break
            bad = bad[0]
            self.bad_function_path.add_node(bad.name)
            self.bad_function_path.add_edge(prev, bad.name)

        # badSource
        bad = bad_function
        while True:
            prev = bad.name
            bad = [func for func in bad.callees if re.match('.*bad.*Source', self.demangle_func_name(func.name))]
            if len(bad) < 1:
                break
            bad = bad[0]
            self.bad_function_path.add_node(bad.name)
            self.bad_function_path.add_edge(prev, bad.name)
