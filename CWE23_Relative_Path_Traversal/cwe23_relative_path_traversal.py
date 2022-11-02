from binaryninja import *
from z3 import *

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
    track_var = lift_list.pop()
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
    return def_ref
for i in range(1, 85) :
    answer = 0   
    filename = f"/home/user/juliet/C/testcases/CWE23_Relative_Path_Traversal/s01/CWE23_Relative_Path_Traversal__char_connect_socket_fopen_{str(i).zfill(2)}.out"
    #filename = f"/home/user/juliet/C/testcases/CWE23_Relative_Path_Traversal/s01/CWE23_Relative_Path_Traversal__char_connect_socket_ifstream_{str(i).zfill(2)}.out"
    #filename = f"/home/user/juliet/C/testcases/CWE23_Relative_Path_Traversal/s01/CWE23_Relative_Path_Traversal__char_connect_socket_ofstream_{str(i).zfill(2)}.out"
    #filename = f"/home/user/juliet/C/testcases/CWE23_Relative_Path_Traversal/s01/CWE23_Relative_Path_Traversal__char_connect_socket_open_{str(i).zfill(2)}.out"
    #filename = f"/home/user/juliet/C/testcases/CWE23_Relative_Path_Traversal/s02/CWE23_Relative_Path_Traversal__char_environment_open_{str(i).zfill(2)}.out"
    sinks = { #sinks
        'fopen': 0,
        '_ZNSt14basic_ifstreamIcSt11char_traitsIcEE4openEPKcSt13_Ios_Openmode' : 1,
        '_ZNSt14basic_ofstreamIcSt11char_traitsIcEE4openEPKcSt13_Ios_Openmode' : 1,
        'open': 0,
        '_open': 0,
        'wopen': 0, 
        '_wopen': 0, 
        'CreateFileA' : 0,
    }

    sources = { #sources
        'recv' : 1,
        'fgets' : 0,
        'fgetws' : 0,
        'strncat' : 0, #strncat(data+dataLen, environment, FILENAME_MAX-dataLen-1);
    }

    bv = process(filename)
    if bv is None :
        continue
    
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
                    print(f"{str(i).zfill(2)}, {hex(ref[1])} : {ref[0]}")
                    answer += 1

print(f"{i} : {answer}")