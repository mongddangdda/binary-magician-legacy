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

def get_related_vars_in_function(bv: BinaryView, function: Function, var: SSAVariable) -> list[SSAVariable]:
    '''
    하나의 함수 내에서 인자 var 값에 영향을 미치는 모든 변수를 리스트 형태로 리턴함
    '''
    
    pass