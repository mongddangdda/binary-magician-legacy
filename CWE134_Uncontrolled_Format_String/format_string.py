from binaryninja import *
from utils.path.path_generator import PathObject, PEdge

source_targets = {
    '__isoc99_fscanf': [2], # 000011b0  int32_t __isoc99_fscanf(FILE* stream, char const* format, ...)
    'recv': [1],
    'fgets': [0],
    'gets': [0], 
    'scanf': [1],
    'read': [1],
    'recv': [1]
}

sink_targets = {
    'puts': [0],
    'fprintf': [1],
    'printf': [0],
    'sprintf': [1],
    'snprintf': [2],
    'vprintf': [0],
    'vfprintf': [1],
    'vsprintf': [1],
    'vnsprintf': [2]
}

def make_sources_and_sinks(bv:BinaryView):
    from utils.utils import make_targets

    sources: list[PEdge] = make_targets(bv=bv, targets=source_targets)
    sinks: list[PEdge] = make_targets(bv)

    return sources, sinks

def solution(bv: BinaryView, path: PathObject):
    pass
