import re
from pathlib import Path
from utils.angr_manager import AngrManager
from utils.path.node import *
from binaryninja.binaryview import BinaryViewType
from binaryninja import *
import networkx as nx

from utils.path.options import PFOption
from utils.path.path_generator import PathObject


def get_all_files_from_path(path: str, depth_level: int = None, file_type: str = '.out') -> list[Path]:

    base_directory = Path(path)

    # is binary?
    if base_directory.is_file():
        return [base_directory]

    pattern = '**/*' # this means visiting all subdirectories recursively

    if depth_level is not None:
        pattern = '/'.join('*' * depth_level)

    file_list = [file for file in base_directory.glob(pattern) if file.is_file() and not file.name.startswith('.') and file.name.endswith(file_type)]
    return file_list

def get_matched_files_from_path(path: str, reg: str = '.*', depth_level: int = None, file_type: str = '.out') -> list[Path]:
    file_list = get_all_files_from_path(path, depth_level, file_type)
    n_file_list = [file for file in file_list if re.match(reg, file.name)]
    return n_file_list

def is_cpp_binary(bv: BinaryViewType) -> bool:
    # TODO: make enum type
    for func in bv.functions:
        if func.name[:2] == '_Z':
            return True
    
    return False

def get_function_cfg(function: Function) -> nx.DiGraph:
    g = nx.DiGraph()

    for bb in function.mlil.ssa_form.basic_blocks:
        for outgoing_edge in bb.outgoing_edges:
            g.add_edge(bb, outgoing_edge.target)

        for incoming_edge in bb.incoming_edges:
            g.add_edge(incoming_edge.source, bb)

    return g

def get_inline_cfg_path(bv: BinaryView, start: int, target: int) -> list[nx.DiGraph]:
    '''
    시작주소와 타겟주소를 입력으로 받아, 함수 내에서 start -> target으로 갈 수 있는 
    control flow 경로를 DiGraph 리스트 형태로 리턴함
    '''
    result = []
    g = get_function_cfg(start.function)
    bb_start = bv.get_basic_blocks_at(start)
    bb_end = bv.get_basic_blocks_at(target)
    
    simple_paths = list( nx.all_simple_edge_paths(g, bb_start, bb_end) )
    for path in simple_paths:
        subgraph = nx.DiGraph()
        subgraph.add_edges_from(path)
        result.append(subgraph)

    return result



#def get_related_vars_in_function(bv: BinaryView, function: Function, var: SSAVariable, path: nx.DiGraph) -> list[SSAVariable]:
def get_related_vars_in_function(function: Function, var: SSAVariable) -> list[SSAVariable]:
    '''
    하나의 함수 내에서 인자 var 값에 영향을 미치는 변수 중 path 내에 존재하는 모든 변수를 리스트 형태로 리턴함

    return : [<ssa rax_5 version 6>, <ssa var_11_1 version 1>, <ssa rax_4 version 5>, <ssa rax_3 version 4>, <ssa var_12 version 2>]
    '''
    result = []

    visited = []
    taint = []
    print(var, type(var))
    taint.append( function.mlil.ssa_form.get_ssa_var_definition(var) )

    while len(taint) > 0:
        track_var = taint.pop()

        # path 내에 존재하는지 확인
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

            taint.append(def_ref)

    return result

def get_entire_call_graph(bv: BinaryView) -> nx.DiGraph:
    graph = nx.DiGraph()

    # entry point
    # export function

    for func in bv.functions:
        for caller in func.callers:
            graph.add_edge(caller, func)
        for callee in func.callees:
            graph.add_edge(func, callee)
    
    return graph

def get_var_initialized_with_argument(func: Function) -> list[SSAVariable]:
    '''
    mlil의 첫 번째 basic block에서 인자와 관련된 초기화를 모두 수행
    '''
    result = []
    
    bb = func.mlil.ssa_form.basic_blocks[0]
    for instr in bb:
        if instr.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA and \
            type(instr.src) == MediumLevelILVarSsa:
            instr.src.src.var.name: str
            if instr.src.src.var.name.startswith('arg'):
                #print('[+]',instr.src.src.var.name, instr.src.src.var.type)
                result.append(instr.dest)

    return result

'''
head
source
sink
path
'''

def is_interprocedurable(func: Function, ssaVar: SSAVariable) -> bool:
    '''
    해당 함수 내의 ssaVar이 인자로부터 초기화되었는지 확인
    True: 인자로부터 초기화
    False: x 
    '''
    vars = get_var_initialized_with_argument(func)
    tainted_vars = get_related_vars_in_function(func, ssaVar)
    for var in vars:
        if var in tainted_vars:
            return True
    return False

def get_call_graph_source_sink(bv: BinaryView, source: Function, src_addr, sink: Function, sink_addr) -> list[nx.DiGraph]:
    
    '''
    TODO: make a customized data structure
    data structure : a list of path that is consisted of source, sink, head ...
    '''


    # get entire call graph
    entire_call_graph = get_entire_call_graph(bv)

    source_group = [source]

    # make source group
    # source 함수의 모든 ancestor 방문
    # - 1. 인자로 초기화되는 변수 추출
    # - 2. taint되는 변수 중 1의 변수가 존재하는지 확인
    # - 3. 존재한다면 상위 ancestor를 방문하기
    # FIXME: source 함수를 호출하는 부분이 여러 곳일 경우 구분하도록 수정해야 함
    # TODO: return 도 전파하기
    #ancestors = nx.ancestors(entire_call_graph, source)
    stack = []

    src_ssa_vars = source.get_llil_at(src_addr).mlil.ssa_form.params
    # taint 된 변수가 인자로 초기화되는지 확인
    for src_ssa_var in src_ssa_vars:
        if type(src_ssa_var.src) == SSAVariable:
            if is_interprocedurable(source, src_ssa_var):
                stack.append(source)
    
    while len(stack) > 0:
        target = stack.pop()
        for caller_site in target.caller_sites:
            src_ssa_vars = source.get_llil_at(caller_site.addr).mlil.ssa_form.params
            for src_ssa_var in src_ssa_vars:
                if type(src_ssa_var.src) == SSAVariable:
                    if is_interprocedurable(target, src_ssa_vars):
                        stack.append(caller_site.function)
                        source_group.append(caller_site.function)
        
    print(source_group)
    # get bad sink

    # make subgraph


    return []

def get_call_graph_source_sink1(bv: BinaryView, source: Function, sink: Function) -> list[nx.DiGraph]:
    
    '''
    TODO: make a customized data structure
    data structure : a list of path that is consisted of source, sink, head ...
    '''
    result = []

    # get entire call graph
    entire_call_graph = get_entire_call_graph(bv)

    source_group = [source]

    # make source group
    ancestors = nx.ancestors(entire_call_graph, source)
    source_group = list(ancestors) + [source]

    # make subgraph
    for head in source_group:
        #print(head)
        paths = list(nx.all_simple_paths(entire_call_graph, head, sink))
        if len(paths) > 0:
            # some data structure with head, source, sink ..? or subgraph
            for path in paths:
                subgraph = entire_call_graph.subgraph(path + source_group)
                result.append(subgraph)

    return result

def update_possible_value(call_path):
    return call_path

def make_targets(bv: BinaryView, targets: dict[str, list[int]]) -> list[PEdge]:
    result = []

    for func_name, taint_args in targets.items():
        functions = bv.get_functions_by_name(func_name)
        if len(functions) < 1:
            continue
        xrefs = bv.get_code_refs(functions[0].start)
        for ref in xrefs:
            ref: ReferenceSource

            mlil = ref.function.get_llil_at(ref.address).mlil

            if mlil is None:
                continue

            if mlil.operation != MediumLevelILOperation.MLIL_CALL or\
                type(mlil.dest) != MediumLevelILConstPtr:
                continue
            
            caller_function = bv.get_function_at(mlil.dest.constant)
            if caller_function is None:
                continue

            result.append( PEdge(start=ref.function, address=ref.address, taint_args=taint_args) )
        
    return result

def make_arithmetic_targets(bv: BinaryView) -> list[PEdge]:
    result = []

    for func in bv.functions:
        for inst in func.mlil.ssa_form.instructions:
            if inst.operation is MediumLevelILOperation.MLIL_SET_VAR_SSA:

                if inst.src.operation not in (MediumLevelILOperation.MLIL_ADD, MediumLevelILOperation.MLIL_MUL):
                    continue

                if inst.src.operation == MediumLevelILOperation.MLIL_ADD:
                    # when A = B + C, taint_args -> [0, 1, 2]
                    result.append(PEdge(start=func, address=inst.address, taint_args=[0,1,2]))
                elif inst.src.operation == MediumLevelILOperation.MLIL_MUL:
                    # when A = B * C, taint_args -> [0, 1, 2]
                    result.append(PEdge(start=func, address=inst.address, taint_args=[0,1,2]))

    return result

def parse_options(options_list: Optional[str] = None):
    options = PFOption.DEFAULT
    if options_list:
        options_list = options_list[0].split(',')
        for option in options_list:
            options |= PFOption[option]

    return options

def check_feasible(path: PathObject) -> bool:
    angr_manager = AngrManager(path=path)
    return angr_manager.check_feasible()

def check_user_controllable(path: PathObject) -> bool:
    return path.check_user_controllable()