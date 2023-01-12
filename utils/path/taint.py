import logging
from binaryninja import *

def get_ssavars_by_var(func: Function, var: Variable):
    ssavars = []

    for ssavar in func.mlil.ssa_vars:
        if ssavar.var == var:
            ssavars.append(ssavar)

    return ssavars

def get_related_var_stack(function: Function, ssavars: list[SSAVariable]) -> list[SSAVariable]:
    '''
    하나의 함수 내에서 주어진 SSAVariable와 관련된 모든 변수를 리턴.
    source 에서 head 를 찾기 위함
    '''
    stack_vars = []

    visited = []
    taint = []
    
    def taint_ssavar(ssavar: SSAVariable):
        stack_vars.append(ssavar)
        def_ref = function.mlil.ssa_form.get_ssa_var_definition(ssavar)
        if def_ref:
            taint.append(def_ref)
        return 


    stack_vars.extend(ssavars)

    # TODO: var use 하는 곳 definition 추가하기
    for var in ssavars:
        taint.append( function.mlil.ssa_form.get_ssa_var_definition(var) )

    while len(taint) > 0:
        track_var = taint.pop()

        
        # TODO: path 내에 존재하는지 확인
        # bb = bv.get_basic_blocks_at(track_var.address)
        # if not path.has_node(bb):
        #     continue
        
        
        # TODO: 전역변수 처리하기
        

        if track_var in visited:
            continue

        visited.append(track_var)

        # FIXME: 모든 Operation에 대해 SSAVariable 리턴하는 클래스 구현
        if track_var.operation not in ( MediumLevelILOperation.MLIL_SET_VAR_SSA, MediumLevelILOperation.MLIL_SET_VAR, \
        MediumLevelILOperation.MLIL_SET_VAR_ALIASED):
            continue

        if track_var.operation == MediumLevelILOperation.MLIL_SET_VAR or \
        track_var.operation == MediumLevelILOperation.MLIL_SET_VAR_SSA:
        # SET_VAR인 경우 

            if track_var.src.operation not in (MediumLevelILOperation.MLIL_VAR_SSA , MediumLevelILOperation.MLIL_VAR_ALIASED, MediumLevelILOperation.MLIL_ADDRESS_OF, MediumLevelILOperation.MLIL_LOAD_SSA, MediumLevelILOperation.MLIL_ADD, MediumLevelILOperation.MLIL_SUB, MediumLevelILOperation.MLIL_MUL ):
                continue

            if track_var.src.operation == MediumLevelILOperation.MLIL_CONST_PTR:
                #SET_VAR의 src가 CONST_PTR인 경우
                continue
            
            elif track_var.src.operation == MediumLevelILOperation.MLIL_VAR_ALIASED:
                # ssavar: SSAVariable = track_var.src.src
                # stack_vars.append(ssavar)
                # def_ref = track_var.ssa_form.function.get_ssa_var_definition(ssavar)
                # if def_ref == None:
                #     continue

                # taint.append(def_ref)
                taint_ssavar(track_var.src.src)
                continue

            elif track_var.src.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
                # like rdx#1 = &var_12
                track_var.src.src: Variable
                _ssavars = get_ssavars_by_var(function, track_var.src.src)
                
                for _ssavar in _ssavars:                    
                    # stack_vars.append(_ssavar)
                    # def_ref = track_var.ssa_form.function.get_ssa_var_definition(_ssavar)
                    # if def_ref == None:
                    #     continue    
                    # taint.append(def_ref)
                    taint_ssavar(_ssavar)
                continue
            
            elif track_var.src.operation == MediumLevelILOperation.MLIL_LOAD_SSA:
                # TODO: 전역변수 처리
                continue
            # src trace
            #var = track_var.src.ssa_form

            elif track_var.src.operation == MediumLevelILOperation.MLIL_LOAD_SSA:
                #LOAD인 경우 해당 src를 참조
                if track_var.src.src == MediumLevelILOperation.MLIL_VAR_SSA:
                    taint_ssavar(track_var.src.src)
                    continue

            elif track_var.src.operation in ( MediumLevelILOperation.MLIL_ADD, MediumLevelILOperation.MLIL_SUB, MediumLevelILOperation.MLIL_MUL):
                if track_var.src.left.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                    taint_ssavar(track_var.src.left.src)
                if track_var.src.right.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                    taint_ssavar(track_var.src.right.src)
                continue

            elif track_var.src.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                taint_ssavar(track_var.src.src)
                continue

            # while type(var) != binaryninja.mediumlevelil.SSAVariable: # MediumLevelILOperation.MLIL_VAR_ALIASED
            #     var = var.src
            
            # raise NotImplemented
            print('zzzzzzzz')
            # stack_vars.append(track_var.src)
            # def_ref = track_var.ssa_form.function.get_ssa_var_definition(var)
            # if def_ref == None:
            #     continue

            # taint.append(def_ref)
            
            # TODO: call 모든 인자 taint 리스트에 추가, a = sub(b) 형태
            # TODO: return된 인자도 taint 리스트에 추가

        # TODO: call 모든 인자 taint 리스트에 추가, sub(b) 형태
        elif track_var.operation == MediumLevelILOperation.MLIL_CALL_SSA:
            pass
            # TODO: return된 인자도 taint 리스트에 추가

            #taint.append(def_ref)
        elif track_var.operation == MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
            try:
                if type(track_var.dest) == SSAVariable:
                    taint_ssavar(track_var.dest)
                if type(track_var.prev) == SSAVariable:
                    taint_ssavar(track_var.prev)
            except:
                logging.debug(f'MLIL_SET_VAR_ALIASED parsing error')
            if track_var.src.operation == MediumLevelILOperation.MLIL_VAR_SSA:
                taint_ssavar(track_var.src.src)
            continue
    return stack_vars