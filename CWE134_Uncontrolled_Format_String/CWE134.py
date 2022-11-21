import os
import sys

sys.path.append(os.path.dirname(os.getcwd()))

from binaryninja import *
from binaryninja.binaryview import BinaryViewType
from binaryninja.function import Function
from utils.runner import Runner
from utils.utils import get_all_files_from_path, get_matched_files_from_path

dangerous_flag = False


def get_func_refs(bv, func_name):
    '''
    함수명을 인자로 입력받아 해당 함수가 참조되는 (함수, 주소)를 튜플 리스트로 반환

    return [(<func: x86_64@0x19be>, 6625), (<func: x86_64@0x193e>, 6496),..., (<func: x86_64@0x1a96>, 6841)]
    '''
    symbol = bv.symbols[func_name]
    if len(symbol) > 1:
        for sym_type in symbol:
            if sym_type.type == SymbolType.ImportedFunctionSymbol:
                symbol = sym_type
                break
    refs = []
    for ref in bv.get_code_refs(symbol.address):
        refs.append((ref.function, ref.address))
    return refs

def forward_taint(bv, use_ref):
    '''
    인자로 받은 instruction문을 forward로 taint analysis 수행
    <mlil: var_20#1 = arg1#0>인 경우, var_20과 arg1에 대해 forward taint analysis 진행
    만약, 분석대상 변수가 dangerous_call에 해당하는 함수의 인자로 
    사용될 경우 위험하다고 판단하여 True 리턴, 아닐 경우 False 리턴

    [+] 분석 시, SET_VAR가 아닌 CALL인 경우에도 처리 필요 --> taint_var처럼 재귀적으로 수행 예정
    [+] dangerous_call의 경우, 인자로 전달하는게 더 나을지도...?
    '''

    trace_list = use_ref
    print('lets foward taint [[+]]', trace_list)
    visited = []
    dangerous_call = ['fgets', 'gets', 'scanf', 'read', 'recv', 'connect']

    while len(trace_list) > 0:
        trace_var = trace_list.pop()
        #print('[[+]] trace_Var = ', trace_var, trace_var.operation)
        if trace_var in visited:
            return
        if trace_var.operation == MediumLevelILOperation.MLIL_SET_VAR or \
            trace_var.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA or \
            trace_var.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
            var = trace_var.ssa_form.dest
            #src에 대해서도 taint 필요 --> taint 완료
            print(trace_var.src.operation)
            src_var = trace_var.src
            use_ref = trace_var.ssa_form.function.get_ssa_var_uses(var)
            print('[[+]] use_ref = ', use_ref)
            for refs in use_ref:
                trace_list.append(refs)
            visited.append(trace_var)
        elif trace_var.operation == MediumLevelILOperation.MLIL_CALL_SSA:
            func_name = bv.get_function_at(trace_var.dest.constant).name
            print('[[-]] func_name = ', func_name)
            if func_name in dangerous_call:
                return True
        elif trace_var.operation == MediumLevelILOperation.MLIL_STORE_SSA:
            if trace_var.src.operation == MediumLevelILOperation.MLIL_CONST:
                #print('[+] ', trace_var.src)
                #return False
                test = 1
    return False
            

def taint_param(bv, taint_func, param_idx):
    '''
    printf(rdi_7)와 같은 taint_func 인자 전달 시, 
    해당하는 파라미터 index를 인자로 받아 taint analysis에 필요한 
    ssa_var_definition 리턴

    0x12a0(rdi_7) --> rdi_7의 ssa_var_definition인 
    rdi_7 = rax_23 반환
    '''
    #print('In_Taint_parma')
    print(taint_func)
    if taint_func == None:
        return None
    var = taint_func.ssa_form.params[param_idx].src
    def_ref = taint_func.function.get_ssa_var_definition(var)
    print('aaa ', def_ref)
    return def_ref

def get_var_from_expr(var):
    '''
    Taint Analysis 분석 시, a=b가 아닌 a=b+1인 경우,
    b+1에서 b를 반환
    '''
    if var.left.operation == MediumLevelILOperation.MLIL_VAR or \
        var.left.operation == MediumLevelILOperation.MLIL_VAR_SSA:
        var = var.left
    else:
        var = var.right
    return var

def taint_var(bv, taint_func, param_idx):
    '''
    Taint analysis를 하려는 함수와 그 함수의 파라미터를 인자로 받음
    Backward로 taint 진행하며 taint variable이 arg가 나온 경우, interprocedure하게 Backward 진행
    기본적으로 a = b인 경우를 taint 진행
    이때, backward로 진행하기 때문에 src에 대해서 taint를 하는데 src의 Operation Type이 다양하기 때문에
    이에 대한 처리 수행
        - 현재 taint variable이 SET_VAR라면? (a = b)
            - 현재 taint variable이 LOAD라면? (a = [b])
                - [b]를 b로 변환
            - b를 구함
            - b가 ADD, SUB와 같은 expression이라면? (a = b+1 / a = b-1)
                - get_var_from_expr() --> b만 추출
            - b가 상수라면?
                - Taint analysis 종료 및 False 반환(위험하지 않음)
            - b가 arg라면?
                - 몇 번재 arg인지 확인 후, 해당 함수의 ref를 찾아 재귀호출
                - func_refs = bv.get_code_refs(trace_var.function.source_function.start)
                    - interprocedure하게 taint 해야하는 함수 리턴
            - 위의 조건에 부합하지 않다면, 계속 taint 진행
        - 현재 taint variable이 ADDRESS_OF라면? (a = &b)
            - 보통 이 경우, taint 하는 변수의 끝인 경우였음
            - a에 대해 forward taint 진행
            - b에 대해서도 forward taint 진행
            - forward taint에서 dangerous call의 인자로 쓰인 경우, 
              taint analysis 종료 및 True 반환(위험함)
        - 현재 taint variable(=instruction)이 CALL인 경우? (a = func1(num) / func2(num))
            - func1(num)이라면, func1 함수에서 num에 대해 forward로 taint analysis 수행
            - forward taint에서 dangerous call의 인자로 쓰인 경우, 
              taint analysis 종료 및 True 반환(위험함)
    '''
    #위험하면 True, 안위험하면 False
    global dangerous_flag
    def_ref = taint_param(bv, taint_func, param_idx)
    taint_list = [def_ref]
    visited = []

    while len(taint_list) > 0:
        load_flag = False
       # print('[+] taint list = ',taint_list)
        trace_var = taint_list.pop()
        if trace_var == None:
            return False
        print('[+] start taint,', trace_var, trace_var.operation)
        if trace_var in visited:
            return
        if trace_var.operation == MediumLevelILOperation.MLIL_SET_VAR or \
            trace_var.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA or \
            trace_var.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
            if trace_var.src.operation == MediumLevelILOperation.MLIL_LOAD_SSA:
                trace_var = trace_var.src
                print('[LOAD!]', trace_var) 
                load_flag=True
            if trace_var.src.operation == MediumLevelILOperation.MLIL_VAR or \
                trace_var.src.operation == MediumLevelILOperation.MLIL_VAR_SSA or \
                load_flag:
                #taint analysis
                var = trace_var.src.ssa_form
                while type(var) != binaryninja.mediumlevelil.SSAVariable:
                    print(var, var.operation, type(var))
                    if var.operation == MediumLevelILOperation.MLIL_ADD or \
                        var.operation == MediumLevelILOperation.MLIL_SUB or \
                        var.operation == MediumLevelILOperation.MLIL_MUL or \
                        var.operation == MediumLevelILOperation.MLIL_DIVS:
                        var = get_var_from_expr(var)
                        print('+++', var)

                    elif var.operation == MediumLevelILOperation.MLIL_CONST_PTR or \
                        var.operation == MediumLevelILOperation.MLIL_CONST:
                        return
                        break
                    var = var.src
               # print(var)
                if 'arg' in var.name:
                    arg_num = var.name.split('arg')[1].split('#')[0]
                  #  print('let\'s taint~', arg_num)
                    func_refs = bv.get_code_refs(trace_var.function.source_function.start)
                    internal_refs = []
                    for ref in func_refs:
                        internal_refs.append((ref.function, ref.address))
                       # print(ref.function)
                    for func, addr in internal_refs:
                        call_instr = func.get_low_level_il_at(addr).mlil
                       # print(call_instr)
                        taint_var(bv, call_instr, int(arg_num)-1)
                def_ref = trace_var.ssa_form.function.get_ssa_var_definition(var)
               # print('[-] def_ref = ', def_ref)
                taint_list.append(def_ref)
            elif trace_var.src.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
                var = trace_var.ssa_form.dest
                src_var = trace_var.src
                #src taint 추가
                while type(src_var) != binaryninja.variable.Variable:
                    src_var = src_var.src
                src_var_name = src_var.name
                src_ref = src_var.function.get_mlil_var_refs(src_var)
                #print("!! ADDRESS OF!", trace_var, var, src_var)
                #print('!! src_ref = ', src_ref)
                for s_r in src_ref:
                    src_instr = s_r.func.get_low_level_il_at(s_r.address).mlil.ssa_form
                #    print('src taint!! = ', src_instr, src_instr.src.operation)
                    #if src_instr.src == MediumLevelILOperation.MLIL_CONST or \
						#src_instr.src == MediumLevelILOperation.MLIL_CONST_PTR:
                    if src_instr.src.operation == MediumLevelILOperation.MLIL_VAR_SSA or \
                        src_instr.src.operation == MediumLevelILOperation.MLIL_VAR or \
                        src_instr.src.operation == MediumLevelILOperation.MLIL_VAR_ALIASED or \
                        src_instr.src.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
                        var_src = src_instr.src.src
                #        print('req', var_src)
                        if var_src.name == src_var_name:
                            lets_forward_taint = [src_instr]
                           # print('qwer', lets_forward_taint)
                            if forward_taint(bv, lets_forward_taint):
                                print('!! dangerous!!')
                                dangerous_flag = True
                                return True
                #print('error?', var)
                
                use_ref = trace_var.ssa_form.function.get_ssa_var_uses(var)
                #print('[+] use_ref= ', use_ref, type(use_ref[0]))
                if forward_taint(bv, use_ref):
                    print('!! dangerous!!')
                    dangerous_flag = True
                    return True
            elif trace_var.operation == MediumLevelILOperation.MLIL_CONST:
                print("wtf?")
                return False
            
        elif trace_var.operation == MediumLevelILOperation.MLIL_CALL_SSA:
            print('THis is CALL!!!')
            call_addr = trace_var.dest.operands[0]
            call_func = bv.get_function_at(call_addr)
            param_list = call_func.parameter_vars
            call_taint_list = []
            for param_var in param_list:
                for ref in call_func.get_mlil_var_refs(param_var):
                    call_taint_list.append(call_func.get_low_level_il_at(ref.address).mlil.ssa_form)

            print(call_taint_list)
            if forward_taint(bv, call_taint_list):
                #print("!!! dandan!!!")
                dangerous_flag = True
                return True
            
        
        visited.append(trace_var)
    #print("real return")
    return False

def solution(bv: BinaryViewType) -> list[Function]:
    dangerous_call = []
    global dangerous_flag
    # dangerous call
    # - printf
    # - fprintf
    # - vprintf, vfprintf, vsnprintf
    # - sprintf, snprintf
    printf_refs = get_func_refs(bv, 'printf')
    #print('analysis start~', printf_refs, len(printf_refs))
    for function, addr in printf_refs:
        print('[!!!!] printf_ref checks', function.name)
        call_instr = function.get_low_level_il_at(addr).mlil
        #print(call_instr)
        dangerous_flag = False
        #1. printf's param len == 1 and params is variable
        if len(call_instr.params) == 1 and \
            call_instr.params[0].operation == MediumLevelILOperation.MLIL_VAR:
            taint_var(bv, call_instr, 0)
            if dangerous_flag:
                dangerous_call.append(function)
                taint_param(bv, call_instr, 0)

    #print(dangerous_call)
    return dangerous_call

if __name__ == '__main__':
    enterprise.connect()
    enterprise.authenticate_with_credentials("", "")
    with enterprise.LicenseCheckout():
        #file_list = get_all_files_from_path(f'/Users/jaehoon/Desktop/C/testcases/CWE134_Uncontrolled_Format_String/s01/only_printf')
        #file_list = [f'/Users/jaehoon/Desktop/C/testcases/CWE134_Uncontrolled_Format_String/s01/only_printf/CWE134_Uncontrolled_Format_String__char_connect_socket_printf_66.out']
        file_list = get_all_files_from_path(f'D:\\binja-snippets\\CWE134_Uncontrolled_Format_String\\s01\\only_printf')
        #file_list = get_all_files_from_path(f'D:\\binja-snippets\\CWE134_Uncontrolled_Format_String\\s01\\only_printf\\test_file')
        #file_list = [f'D:\\binja-snippets\\CWE134_Uncontrolled_Format_String\\s01\\only_printf']
		#runner = Runner(solution, file_list)
        #runner.run(cpp_only=True)
        '''for file_ in file_list:
            with open_view(file_) as bv:
                print('[+]', os.path.basename(file_))
                solution(bv)
                print('------------------------------')
        #print(f'Score = {correct}/{correct+wrong}')
        print('this i stest')
		'''
        runner = Runner(solution, file_list)
        runner.run()

# TODO 사항
# 안되는 케이스
# - - 전역변수 처리 (CWE134_Uncontrolled_Format_String__char_console_printf_68)