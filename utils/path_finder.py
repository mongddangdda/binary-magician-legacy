from binaryninja import *
import networkx as nx
from dataclasses import dataclass
import builtins
'''
TODO: list
- [ ] docstring format에 맞게 수정하기 및 영어로 작성
- [ ] ... 
'''

@dataclass
class target:
    type: str # 'source' or 'sink' TODO: update union type?
    addr: int 
    function: Function # containing function
    ssavars: list[SSAVariable]
    args: list[int]

def get_target_by_addr_args(bv: BinaryView, type: str, addr: int, args: list[int]) -> target:
    function = bv.get_functions_containing(addr=addr)[0]
    ssavars = []
    for arg_num in args:
        #_taint_param = caller.function.get_llil_at(caller.address).mlil.ssa_form.params[int(arg_num)-1]
        _taint_param = function.get_llil_at(addr).mlil.ssa_form.params[arg_num]
        if builtins.type(_taint_param) is MediumLevelILVarSsa:
            ssavars.append(_taint_param.src)
    return target(type=type, addr=addr, function=function, ssavars=ssavars, args=args)

def get_target_by_func_ssavars(bv: BinaryView, type: str, function: Function, ssavars: list[SSAVariable]) -> target:
    pass

@dataclass
class callHierarchy:
    head: Function
    source: target
    sink: target
    graph: nx.DiGraph
    # functions: dict

class PathObj():
    def __init__(self) -> None:
        pass


class PathFinder():
    '''
    source -> sink 경로를 관리하기 위한 클래스

    ### feature
    - 바이너리 전체의 call graph를 생성한 뒤, 사용자가 입력한 source 와 sink 까지의 모든 경로를 리턴
    - 방문한 함수 내의 인자 사이의 dependency를 저장한 테이블을 관리함
    - 사용자가 source 와 sink 를 입력하면, 가능한 경로 모든 경로를 리턴
    - 사용자가 입력한 source와 sink는 list 형태일 것
    - 리턴된 경로는 추후 updater에서 PossibleValueSet을 업데이트하는 데에 사용됨
    
    ### todo list
    - [x] call path 만들기 (단순 function - function)
    - [ ] call 간 호출 위치로 더 자세한 path 만들기 ( (function, call site, argument) - (function, call site, argument) )
    '''
    def __init__(self, bv: BinaryView) -> None:
        self.bv = bv
        self.graph = nx.DiGraph() # entire graph
        self.sources: list[target] = []
        self.paths: list[callHierarchy] = []
        self.tainted = dict()

        self._make_entire_call_graph()

    def _make_entire_call_graph(self):
        '''전체 function call graph 작성하기'''
        for func in self.bv.functions:
            for caller in func.callers:
                self.graph.add_edge(caller, func)
            for callee in func.callees:
                self.graph.add_edge(func, callee)
    
    def get_related_vars_in_function(self, function: Function, vars: list[SSAVariable]) -> list[SSAVariable]:
        '''
        하나의 함수 내에서 인자 var 값에 영향을 미치는 변수 중 path 내에 존재하는 모든 변수를 리스트 형태로 리턴함

        return : [<ssa rax_5 version 6>, <ssa var_11_1 version 1>, <ssa rax_4 version 5>, <ssa rax_3 version 4>, <ssa var_12 version 2>]
        TODO: 
        1. function call의 인자일 때, 다른 인자들을 다 taint로 하기
           - function dataflow analysis를 적용하여 인자간 taint 관계 찾기
        2. 현재로써는 실제 실행가능한 basic block을 구분하지 못함
           - function 내 dataflow analysis 적용
        '''
        result = []

        visited = []
        taint = []
        #print(vars)
        for var in vars:
            taint.append( function.mlil.ssa_form.get_ssa_var_definition(var) )

        while len(taint) > 0:
            track_var = taint.pop()

            # TODO: path 내에 존재하는지 확인
            # bb = bv.get_basic_blocks_at(track_var.address)
            # if not path.has_node(bb):
            #     continue


            if track_var in visited:
                continue

            visited.append(track_var)

            # FIXME: 모든 Operation에 대해 SSAVariable 리턴하는 클래스 구현
            if track_var.operation not in ( MediumLevelILOperation.MLIL_SET_VAR_SSA, MediumLevelILOperation.MLIL_SET_VAR, \
            MediumLevelILOperation.MLIL_VAR_PHI ):
                continue

            if track_var.operation == MediumLevelILOperation.MLIL_SET_VAR or \
            track_var.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
            # SET_VAR인 경우 
                if track_var.src.operation == MediumLevelILOperation.MLIL_CONST_PTR:
                    #SET_VAR의 src가 CONST_PTR인 경우
                    continue
                if track_var.src.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
                    continue
                # src trace
                var = track_var.src.ssa_form

                if var.operation == MediumLevelILOperation.MLIL_LOAD_SSA:
                    #LOAD인 경우 해당 src를 참조
                    var = var.src
                if var.operation == MediumLevelILOperation.MLIL_ADD or \
                var.operation == MediumLevelILOperation.MLIL_SUB or \
                var.operation == MediumLevelILOperation.MLIL_MUL or \
                var.operation == MediumLevelILOperation.MLIL_DIVS:
                    #src가 operation인 경우, VAR 참조
                    if var.left.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                        var = var.left
                    else:
                        var = var.right
                while type(var) != binaryninja.mediumlevelil.SSAVariable: # MediumLevelILOperation.MLIL_VAR_ALIASED
                    var = var.src
                
                result.append(var)
                def_ref = track_var.ssa_form.function.get_ssa_var_definition(var)
                if def_ref == None:
                    continue

                # TODO: call 모든 인자 taint 리스트에 추가
                

                taint.append(def_ref)

        return result

    def param_idx_to_ssavar(self, func: Function, addr: int, idx: int) -> SSAVariable:
        '''
        convert argument index -> SSAVariable
        ex) arg1 -> params[0]
        '''
        return func.get_llil_at(addr).mlil.ssa_form.params[idx-1]


    def backward_analysis_from_target(self, target: target) -> set[Function]:
        '''
        ### 000014b2      __isoc99_fscanf(stream: stdin, format: "%c", &var_12)
        When like above, the source_addr is 0x14b2 and the arg_idxs is [2] (var_12)
        '''
        source_group = set()
        #print(target)
        # start = self.bv.get_functions_containing(source_addr)[0] # get source function
        # #print(start)
        # ssavars = []
        # for arg_num in arg_idxs:
        #     _taint_param = self.param_idx_to_ssavar(start, source_addr, arg_num)
        #     _taint_param = start.get_llil_at(source_addr).mlil.ssa_form.params[arg_num]
        #     if type(_taint_param) is MediumLevelILVarSsa:
        #         ssavars.append(_taint_param.src)
        # source_group.add(start)

        start = target.function
        ssavars = target.ssavars
        source_group.add(start)

        tmp = [(start, ssavars)]
        while len(tmp) > 0:
            func, ssavars = tmp.pop()
            tainted = self.get_related_vars_in_function(func, ssavars) # 해당 함수 내의 특정 변수들로 taint 된 변수 리스트 리턴
            print(ssavars, tainted)
            # TODO: save function's tainted varaible
            if self.tainted.get(func) is None:
                self.tainted[func] = dict()
            self.tainted[func][tuple(ssavars)] = tainted
            
            args = [(arg, arg.var.name.split('arg')[1]) for arg in tainted if arg.var.name.startswith('arg')]
            if len(args) < 1: # argument로 초기화된 변수가 없을 때는 패스
                continue

            arg_nums = [arg_num for _, arg_num in args]
            refs = self.bv.get_code_refs(func.start)
            for caller in refs:
                _ssavars = []
                for arg_num in arg_nums:
                    _taint_param = self.param_idx_to_ssavar(caller.function, caller.address, int(arg_num))
                    #_taint_param = caller.function.get_llil_at(caller.address).mlil.ssa_form.params[int(arg_num)-1]
                    if type(_taint_param) is MediumLevelILVarSsa:
                        _ssavars.append(_taint_param.src)
                
                # print('function', caller.function)
                source_group.add(caller.function)
                tmp.append((caller.function, _ssavars))

        return source_group

    def get_simple_path(self, source: target, sink: target) -> list[callHierarchy]:
        '''source 부터 sink 까지 있을 수 있는 노드 그래프에서의 path 리턴'''
        source_group = self.backward_analysis_from_target(source)
        # print(source_group)
        result = []

        # when there are source and sink in same function.
        if source.function == sink.function:
            subgraph = self.graph.subgraph([source.function]).copy()
            result.append(callHierarchy(head=source.function, source=source, sink=sink, graph=subgraph))
            return result

        for head in source_group:
            if head == source.function:
                paths_to_source = [source.function]
            else:
                paths_to_source = list(nx.all_simple_paths(self.graph, head, source.function))
            
            #print('path_to_source', paths_to_source)
            if head == sink.function:
                paths_to_sink = [sink.function]
            else:
                paths_to_sink = list(nx.all_simple_paths(self.graph, head, sink.function))

            if len(paths_to_sink) > 0:
                #print('head', head)
                # some data structure with head, source, sink ..? or subgraph
                for path_to_sink in paths_to_sink:
                    #print('path_to_sink', path_to_sink)
                    for path_to_source in paths_to_source:
                        #print('path_to_source', path_to_source)
                        subgraph = self.graph.subgraph(list(path_to_sink) + list(path_to_source)).copy()
                        result.append(callHierarchy(head=head, source=source, sink=sink, graph=subgraph))
        
        # update edge with call_sites attribute
        for callgraph in result:
            callgraph: callHierarchy
            edges = nx.bfs_edges(callgraph.graph, callgraph.head)
            for start, end in edges:
                #print('start', start, end)
                call_sites: list[ReferenceSource] = []
                for call_site in start.call_sites: # start 내에서 end를 호출한 위치
                    call_site: ReferenceSource
                    mlil = call_site.function.get_llil_at(call_site.address).mlil.ssa_form
                    print('call_site', call_site)
                    if mlil.operation == MediumLevelILOperation.MLIL_CALL:
                        try:
                            if mlil.dest.constant == end.start:
                                call_sites.append(call_site)
                        except:
                            print('indirect call!')
                nx.set_edge_attributes(callgraph.graph, {(start, end): {'call_sites': call_sites}})
                print(start, end, call_sites)

        return result


    def backward_analysis_from_target2(self, target: target) -> set[Function]:
        '''
        TODO: 각 노드를 target 타입으로 사용하는 새로운 backward analysis graph 생성함수
        '''
        # source_group = set()

        # start = target.function
        # ssavars = target.ssavars
        # source_group.add(start)

        # tmp = [(start, ssavars)]
        # while len(tmp) > 0:
        #     func, ssavars = tmp.pop()
        #     tainted = self.get_related_vars_in_function(func, ssavars) # 해당 함수 내의 특정 변수들로 taint 된 변수 리스트 리턴
        #     #print(tainted)

        #     args = [(arg, arg.var.name.split('arg')[1]) for arg in tainted if arg.var.name.startswith('arg')]
        #     if len(args) < 1: # argument로 초기화된 변수가 없을 때는 패스
        #         continue

        #     arg_nums = [arg_num for _, arg_num in args]
        #     refs = self.bv.get_code_refs(func.start)
        #     for caller in refs:
        #         _ssavars = []
        #         for arg_num in arg_nums:
        #             _taint_param = self.param_idx_to_ssavar(caller.function, caller.address, int(arg_num))
        #             #_taint_param = caller.function.get_llil_at(caller.address).mlil.ssa_form.params[int(arg_num)-1]
        #             if type(_taint_param) is MediumLevelILVarSsa:
        #                 _ssavars.append(_taint_param.src)
                
        #         # print('function', caller.function)
        #         source_group.add(caller.function)
        #         tmp.append((caller.function, _ssavars))
        #return source_group
        pass

    def get_backward_path(self, source: target, sink: target):
        source
        pass

    def get_call_sites_by_path(self, callgraph: callHierarchy):
        functions = dict()
        for start, end, data in callgraph.graph.edges(data=True):
            print(start, end, data)
            for call_site in data['call_sites']:
                functions[end] = { call_site : [] }
                instr :  mediumlevelil.MediumLevelILCallSsa = start.get_llil_at(call_site.address).mlil.ssa_form
                
                # 일반적인 함수 호출일 때
                if instr.operation == MediumLevelILOperation.MLIL_CALL_SSA:
                    for idx, param in enumerate(start.get_llil_at(call_site.address).mlil.ssa_form.params):
                        # TODO: param type에 따라 처리하기
                        if type(param) == MediumLevelILVarSsa:
                            functions[end][call_site].append(
                                ( f'arg{idx}', param.src, start.get_llil_at(call_site.address).mlil.ssa_form.get_ssa_var_possible_values(param.src) )
                            )
                        if type(param) == MediumLevelILConst:
                            functions[end][call_site].append(
                                ( f'arg{idx}', param, PossibleValueSet.constant(param.constant) )
                            )
        return functions
    
    def update_possibleValue(self, function: Function, ref: ReferenceSource, data: list[set]):
        
        function.clear_all_user_var_values()
       
        for name, ssavar, possiblevalue in data:
            for instr in function.mlil.ssa_form.basic_blocks[0]:
                if instr.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA and \
                    type(instr.src) == MediumLevelILVarSsa:
                    instr.src.src.var.name: str
                    if instr.src.src.var.name.startswith(name):
                        var = instr.dest.var
                        function.set_user_var_value(var=var, def_addr=instr.address, value=possiblevalue)
    

    def save_path_to_image(self, graph: nx.DiGraph, file: str):
        '''source - sink path를 이미지로 저장하기'''
        edge_labels = nx.get_edge_attributes(graph, 'call_sites')

        def make_edge_name(call_sites):
            #return ''.join([str(call_site.function.get_llil_at(call_site.address).hlil) for call_site in call_sites])
            return ''.join(['call at '+hex(call_site.address) for call_site in call_sites])

        formatted_edge_labels = {(elem[0],elem[1]): make_edge_name(edge_labels[elem]) for elem in edge_labels}
        # attribute 데이터가 있으면 아래의 position 구하는 부분에서 error 발생하기 때문에 지워줌
        for _, _, call_sites in graph.edges(data=True):
            call_sites.clear()

        pos = nx.nx_pydot.graphviz_layout(graph, prog='dot')
        nx.draw(graph, pos=pos, with_labels=True)
        nx.draw_networkx_edge_labels(graph, pos=pos, edge_labels=formatted_edge_labels)
        
        try:
            import matplotlib.pyplot as plt
            plt.savefig(file)
        except:
            print('file save error!')


    def show_graph(self, graph: nx.DiGraph):
        
        import networkx as nx
        a = nx.DiGraph()

        for start, end in graph.edges:
            name1 = start.name if start.name is not None else str(start.addr)
            name2 = end.name if end.name is not None else str(end.addr)
            a.add_edge(name1, name2)

        def show_using_pygraphviz(graph):
            # graphviz 설치해야함. 맥에서는 brew로 설치가능
            # 그 외 pygraphviz matplotlib을 pip로 설치
            import matplotlib.pyplot as plt
            pos = nx.nx_pydot.graphviz_layout(graph, prog='dot')
            nx.draw(graph, pos=pos, with_labels=True)
            plt.savefig('example.png')

        def show_using_pyvis(graph):
            # pyvis pip로 설치
            from pyvis.network import Network
            net = Network(directed=True, notebook=True)
            net.from_nx(a)
            net.show('example.html')

        show_using_pygraphviz(a)
        show_using_pyvis(a)

    def save_bndb_file_by_path(self):
        # TODO: BinaryView에서 구한 path에 해당하는 부분을 highlight한 뒤 bndb 파일로 저장하기
        pass