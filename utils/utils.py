import re
from pathlib import Path
from binaryninja.binaryview import BinaryViewType
from binaryninja import *
import networkx as nx

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

def get_function_cfg(function) -> nx.DiGraph:
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



def get_related_vars_in_function(bv: BinaryView, function: Function, var: SSAVariable, path: nx.DiGraph) -> list[SSAVariable]:
    '''
    하나의 함수 내에서 인자 var 값에 영향을 미치는 변수 중 path 내에 존재하는 모든 변수를 리스트 형태로 리턴함

    return : [<ssa rax_5 version 6>, <ssa var_11_1 version 1>, <ssa rax_4 version 5>, <ssa rax_3 version 4>, <ssa var_12 version 2>]
    '''
    result = []

    visited = []
    taint = []
    taint.append( function.mlil.ssa_form.get_ssa_var_definition(var) )

    while len(taint) > 0:
        track_var = taint.pop()

        # path 내에 존재하는지 확인
        bb = bv.get_basic_blocks_at(track_var.address)
        if not path.has_node(bb):
            continue


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