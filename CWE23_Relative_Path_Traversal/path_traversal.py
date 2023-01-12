from binaryninja import *
from utils.path.edge import PEdge
from utils.path.path_generator import PathObject

source_targets = {
    '__isoc99_fscanf': [2], # 000011b0  int32_t __isoc99_fscanf(FILE* stream, char const* format, ...)
    'recv': [1],
    'fgets': [0],
    'gets': [0], 
    'scanf': [1],
    'read': [1],
    'recv': [1],
    'fgetws' : [0],
    'strncat' : [0]
}

sink_targets = {
    'fopen': [0],
    'open': [0],
    '_open': [0],
    'wopen': [0],
    '_wopen': [0],
    'CreateFileA': [0],
}

def make_sources_and_sinks(bv:BinaryView):
    from utils.utils import make_targets

    sources: list[PEdge] = make_targets(bv=bv, targets=source_targets)
    sinks: list[PEdge] = make_targets(bv=bv, targets=sink_targets)

    return sources, sinks

def solution(bv: BinaryView, path: PathObject) -> list[Function]:
    result = []

    return result