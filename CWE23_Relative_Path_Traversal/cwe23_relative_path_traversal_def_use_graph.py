from utils.utils import get_all_files_from_path
from utils.runner import Runner
from binaryninja.function import Function
from binaryninja.binaryview import BinaryViewType
import os
import sys
from binaryninja import *
import itertools

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def process(filename):
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    else:
        if filename is None:
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
    else:
        return None
    refs = []
    for ref in bv.get_code_refs(symbol.address):
        refs.append((ref.function, ref.address))
    return refs


def get_param_refs(refs, param_idx):
    dangerous_call = []
    for function, addr in refs:
        call_instr = function.get_low_level_il_at(addr).mlil.ssa_form
        param = call_instr.ssa_form.params[param_idx]
        if param.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            dangerous_call.append((call_instr, addr))
        else:
            return None
    return dangerous_call


def trace_var(dangerous_call, param_idx):
    var = dangerous_call[0].ssa_form.params[param_idx].src
    def_ref = dangerous_call[0].function.get_ssa_var_definition(var)
    return def_ref


def chaining(graph, k, v):
    get_v = graph.get(k, [])
    if v not in get_v:
        graph[k] = graph.get(k, [])+[v]


def backward_def_use_chain(bv, instr_list, b_def_use_graph):
    instr = instr_list.pop()
    dest_var = instr.dest
    if instr.operation == MediumLevelILOperation.MLIL_CALL_SSA:  # intra procedure
        symbol = bv.get_symbol_at(instr.dest.constant)
        for param in instr.params:
            for var in param.vars_read:
                chaining(b_def_use_graph, symbol.name, var)
                instr_list.append(instr.function.get_ssa_var_definition(var))
        for dest_var in instr.output:
            chaining(b_def_use_graph, dest_var, symbol.name)
        return
    elif instr.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
        # var_1018 @ mem#1 -> mem#2 = 0x2f706d742f
        return
    elif instr.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA\
            or instr.operation == MediumLevelILOperation.MLIL_SET_VAR:
        src_var = instr.src
        if src_var.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
            # var_1018 @ mem#1 -> mem#2 = 0x2f706d742f
            chaining(b_def_use_graph, dest_var, src_var.src)
            return
        elif src_var.operation == MediumLevelILOperation.MLIL_ADD or \
                src_var.operation == MediumLevelILOperation.MLIL_SUB or \
                src_var.operation == MediumLevelILOperation.MLIL_MUL or \
                src_var.operation == MediumLevelILOperation.MLIL_DIVS:
            if src_var.left.operation == MediumLevelILOperation.MLIL_VAR_SSA and \
                    src_var.right.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                chaining(b_def_use_graph, dest_var, src_var.left.src)
                instr_list.append(
                    src_var.left.function.get_ssa_var_definition(src_var.left.src))
                chaining(b_def_use_graph, dest_var, src_var.right.src)
                instr_list.append(
                    src_var.right.function.get_ssa_var_definition(src_var.right.src))
                return
            elif src_var.left.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                chaining(b_def_use_graph, dest_var, src_var.left.src)
                instr_list.append(
                    src_var.left.function.get_ssa_var_definition(src_var.left.src))
                return
            elif src_var.right.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                chaining(b_def_use_graph, dest_var, src_var.right.src)
                instr_list.append(
                    src_var.right.function.get_ssa_var_definition(src_var.right.src))
                return
        elif src_var.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            if 'arg' in src_var.src.name:  # not support
                return
            chaining(b_def_use_graph, dest_var, src_var.src)
            instr_list.append(
                src_var.function.get_ssa_var_definition(src_var.src))
            return


def forward_def_use_chain(bv, instr_list, f_def_use_graph):
    instr_zip = instr_list.pop()
    instr = instr_zip[0]
    trace_var = instr_zip[1]
    if instr.operation == MediumLevelILOperation.MLIL_IF:  # not support
        return
    elif instr.operation == MediumLevelILOperation.MLIL_RET:  # not support
        # return rax_2#6
        return
    dest_var = instr.dest
    if dest_var in f_def_use_graph.keys():  # check visited
        return
    elif instr.operation == MediumLevelILOperation.MLIL_CALL_SSA:
        symbol = bv.get_symbol_at(instr.dest.constant)
        for param in instr.params:
            for var in param.vars_read:
                if var == trace_var:
                    chaining(f_def_use_graph, var, symbol.name)
        for dest_var in instr.output:
            uses_list = instr.function.get_ssa_var_uses(dest_var)
            instr_list.extend([(x, y) for x, y in itertools.zip_longest(
                uses_list, [], fillvalue=dest_var)])
            chaining(f_def_use_graph, symbol.name, dest_var)
        return
    elif instr.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED:  # not support
        return
    elif instr.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
        src_var = instr.src
        if src_var.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
            chaining(f_def_use_graph, src_var.src, dest_var)
            uses_list = src_var.function.get_ssa_var_uses(dest_var)
            instr_list.extend([(x, y) for x, y in itertools.zip_longest(
                uses_list, [], fillvalue=dest_var)])
        elif src_var.operation == MediumLevelILOperation.MLIL_VAR_SSA:
            chaining(f_def_use_graph, src_var.src, dest_var)
            uses_list = src_var.function.get_ssa_var_uses(dest_var)
            instr_list.extend([(x, y) for x, y in itertools.zip_longest(
                uses_list, [], fillvalue=dest_var)])
        elif src_var.operation == MediumLevelILOperation.MLIL_ADD or \
                src_var.operation == MediumLevelILOperation.MLIL_SUB or \
                src_var.operation == MediumLevelILOperation.MLIL_MUL or \
                src_var.operation == MediumLevelILOperation.MLIL_DIVS:
            if src_var.left.operation == MediumLevelILOperation.MLIL_VAR_SSA and \
                    src_var.right.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                if src_var.left.src == trace_var:
                    chaining(f_def_use_graph, src_var.left.src, dest_var)
                    uses_list = src_var.function.get_ssa_var_uses(dest_var)
                    instr_list.extend([(x, y) for x, y in itertools.zip_longest(
                        uses_list, [], fillvalue=dest_var)])
                elif src_var.right.src == trace_var:
                    chaining(f_def_use_graph, src_var.right.src, dest_var)
                    uses_list = src_var.function.get_ssa_var_uses(dest_var)
                    instr_list.extend([(x, y) for x, y in itertools.zip_longest(
                        uses_list, [], fillvalue=dest_var)])
            elif src_var.left.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                if src_var.left.src == trace_var:
                    chaining(f_def_use_graph, src_var.left.src, dest_var)
                    uses_list = src_var.function.get_ssa_var_uses(dest_var)
                    instr_list.extend([(x, y) for x, y in itertools.zip_longest(
                        uses_list, [], fillvalue=dest_var)])
            elif src_var.right.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                if src_var.right.src == trace_var:
                    chaining(f_def_use_graph, src_var.right.src, dest_var)
                    uses_list = src_var.function.get_ssa_var_uses(dest_var)
                    instr_list.extend([(x, y) for x, y in itertools.zip_longest(
                        uses_list, [], fillvalue=dest_var)])
        elif src_var.operation == MediumLevelILOperation.MLIL_SX:
            uses_list = src_var.function.get_ssa_var_uses(dest_var)
            instr_list.extend([(x, y) for x, y in itertools.zip_longest(
                uses_list, [], fillvalue=dest_var)])
    elif instr.operation == MediumLevelILOperation.MLIL_STORE_SSA:  # not support
        return
    elif instr.operation == MediumLevelILOperation.MLIL_VAR_PHI:
        for src_var in instr.src:
            if src_var == trace_var:
                chaining(f_def_use_graph, src_var, dest_var)
                uses_list = instr.function.get_ssa_var_uses(dest_var)
                instr_list.extend([(x, y) for x, y in itertools.zip_longest(
                    uses_list, [], fillvalue=dest_var)])


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


def recursive_dfs(v, graph, discovered):
    discovered.append(v)
    for w in graph[v]:
        if (w in graph) and (w not in discovered):
            discovered = recursive_dfs(w, graph, discovered)
    return discovered


def solution(bv: BinaryViewType) -> list[Function]:

    result = []  # spicious function list

    sinks = {  # sinks
        'fopen': 0,
        'open': 0,
        '_open': 0,
        'wopen': 0,
        '_wopen': 0,
        'CreateFileA': 0,
    }

    sources = {  # sources
        'recv': 1,
        'fgets': 0,
        'fgetws': 0,
        # strncat(data+dataLen, environment, FILENAME_MAX-dataLen-1);
        'strncat': 0,
    }

    for func in bv.functions:
        if demangle_function(bv, func) == "std::basic_ifstream<char, std::char_traits<char> >::open" or\
                demangle_function(bv, func) == "std::basic_ofstream<char, std::char_traits<char> >::open":
            sinks[func.name] = 1

    b_def_use_graph = {}  # backward graph
    f_def_use_graph = {}  # forward graph

    for sink, sink_idx in sinks.items():
        symbols_ref = get_func_refs(bv, sink)
        if symbols_ref is None:
            continue
        def_refs = get_param_refs(symbols_ref, sink_idx)
        for ref in def_refs:
            taint_sink = trace_var(ref, sink_idx)
            taint_list = [taint_sink]
            while (len(taint_list) > 0):  # make backward_def_use_graph
                backward_def_use_chain(bv, taint_list, b_def_use_graph)
            for key, values in b_def_use_graph.items():
                for value in values:
                    if value not in b_def_use_graph.keys():  # find v, make Forward_DefUse_chain
                        taint_list = [
                            (value.function.mlil.ssa_form.get_ssa_var_definition(key), key)]
                        while (len(taint_list) > 0):
                            forward_def_use_chain(
                                bv, taint_list, f_def_use_graph)
                        sink_bool, source_bool = False, False
                        for items in f_def_use_graph.values():
                            for item in items:
                                if item in sinks.keys():
                                    sink_bool = True
                                if item in sources.keys():
                                    source_bool = True
                                if sink_bool and source_bool:
                                    return bv.get_functions_containing(value.function.start)
        b_def_use_graph.clear()
        f_def_use_graph.clear()
    return result


if __name__ == '__main__':
    file_list = get_all_files_from_path(
        f'/home/user/juliet/C/testcases/CWE23_Relative_Path_Traversal/s01/')
    runner = Runner(solution, file_list)
    runner.run(cpp_only=True)
