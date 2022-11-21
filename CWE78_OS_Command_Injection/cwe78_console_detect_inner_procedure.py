import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from binaryninja import *
from binaryninja.binaryview import BinaryViewType
from binaryninja.function import Function
from utils.runner import Runner
from utils.utils import get_matched_files_from_path


def process(filename) :
    if len(sys.argv) > 1 :
        filename = sys.argv[1]
    else :
        if filename is None :
            binaryninja.log_warn("No File Specified")
            sys.exit(1)
    bv = binaryninja.BinaryViewType.get_view_of_file(filename)
    return bv

def get_func_refs(bv, func_name):
    symbol = bv.symbols[func_name]
    if len(symbol) > 1:
        for sym_type in symbol:
            if sym_type.type == SymbolType.ImportedFunctionSymbol:
                symbol = sym_type
            break
    else :
        return None
    refs = []
    for ref in bv.get_code_refs(symbol.address) :
        refs.append((ref.function, ref.address))
    return refs

def get_param_refs(refs, param_idx):
    dangerous_call = []
    for function, addr in refs:
        call_instr = function.get_low_level_il_at(addr).mlil
        param = call_instr.ssa_form.params[param_idx]
        if param.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            dangerous_call.append((call_instr, addr))
        else :
            return None
    return dangerous_call

def trace_var(dangerous_call, param_idx):
    var = dangerous_call[0].ssa_form.params[param_idx].src
    def_ref = dangerous_call[0].function.get_ssa_var_definition(var)
    return def_ref

def lift_target(lift_list, visited):
    def_ref = None
    track_var = lift_list.pop()
    if track_var is None:
        return
    if track_var.dest in visited:
        return
    visited.append(track_var.dest)
    if track_var.operation == MediumLevelILOperation.MLIL_SET_VAR or \
		track_var.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:  #SET_VAR 인 경우
        if track_var.src.operation == MediumLevelILOperation.MLIL_CONST_PTR: #SET_VAR의 src가 CONST_PTR인 경우
            return
        elif track_var.src.operation == MediumLevelILOperation.MLIL_ADDRESS_OF: #SET_VAR의 src가 address인 경우
            return

        var = track_var.src.ssa_form
        if var.operation == MediumLevelILOperation.MLIL_LOAD_SSA: #LOAD인 경우 해당 sec 참조
            var = var.src
        elif var.operation == MediumLevelILOperation.MLIL_ADD or \
            var.operation == MediumLevelILOperation.MLIL_SUB or \
            var.operation == MediumLevelILOperation.MLIL_MUL or \
            var.operation == MediumLevelILOperation.MLIL_DIVS: #src가 operation인 경우, var 참조
            if var.left.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                var = var.left
            else:
                var = var.right

        while type(var) != binaryninja.mediumlevelil.SSAVariable:
            var = var.src
        def_ref = track_var.ssa_form.function.get_ssa_var_definition(var)
        if def_ref == None :
            #1. 데이터의 시작점
            #2. function의 arg
            pass
        lift_list.append(def_ref)

    elif track_var.operation == MediumLevelILOperation.MLIL_CALL: #CALL인 경우 파라미터 변수 추적
        pass

    elif track_var.operation == MediumLevelILOperation.MLIL_VAR_PHI:
        pass
    if def_ref == None:
        return
    return def_ref

def demangle_function(bv, func: Function) -> str:
    if func.name[:2] == '_Z':
        if bv.platform.name.split('-')[0] == 'linux':
            name = demangle_gnu3(bv.arch, func.name)[1]
        elif bv.platform.name.split('-')[0] == 'windows':
            name = demangle_ms(bv.arch, func.name)[1]
        func_name = get_qualified_name(name)
        return func_name
    else:
        return func.name

def solution(bv: BinaryViewType) -> list[Function]:

    result = [] # spicious function list

    sinks = { #sinks
        'execl': 3,
        'execlp': 3,
        'popen': 0,
        'system': 0,
    }

    sources = { #sources
        'recv' : 1,
        'fgets' : 0,
        'fgetws' : 0,
        'strncat' : 0, #strncat(data+dataLen, environment, FILENAME_MAX-dataLen-1);
    }

    try :
        for sink, sink_idx in sinks.items() :
            for source, source_idx in sources.items() : #sources의 visited 확인
                symbols_ref = get_func_refs(bv, source)
                if symbols_ref is None :
                    continue
                def_refs = get_param_refs(symbols_ref, source_idx)
                for ref in def_refs:
                    lift_var = trace_var(ref, source_idx)
                    lift_list = [lift_var]
                    source_visited = []
                    while len(lift_list) > 0:
                        lift_target(lift_list, source_visited)

            symbols_ref = get_func_refs(bv, sink) #sinks의 visited 확인
            if symbols_ref is None :
                    continue
            def_refs = get_param_refs(symbols_ref, sink_idx)
            for ref in def_refs:
                lift_var = trace_var(ref, sink_idx)
                lift_list = [lift_var]
                sink_visited = []
                while len(lift_list) > 0:
                    lift_target(lift_list, sink_visited)
                for sink in sink_visited : #sources와 sinks 둘 모두 방문했으면 tainted 판단.
                    if sink in source_visited :
                        return bv.get_functions_containing(ref[1])
    except:
        pass

    return result

if __name__ == '__main__':
    binary_path = '/Users/kiddo/workspace/C/testcases/CWE78_OS_Command_Injection/s01'
    testcase_pattern = 'CWE78_OS_Command_Injection*'
    file_list = get_matched_files_from_path(binary_path, testcase_pattern)
    runner = Runner(solution, file_list)
    runner.run()
