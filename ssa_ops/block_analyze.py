def blockAnalyze(block, variable_ops): # return map
    for inst in block:
        if inst.operation == 'MLIL_SET_VAR':
            continue
        elif ins.operation == 'MLIL_SET_VAR_ALIASED':
            continue
        elif inst.operation == 'MLIL_SET_VAR':
            continue
        elif inst.operation == 'MLIL_SET_VAR_ALIASED':
            continue
        elif inst.operation == 'MLIL_SET_VAR_ALIASED_FIELD':
            continue
        elif inst.operation == 'MLIL_SET_VAR_FIELD':
            continue
        elif inst.operation == 'MLIL_SET_VAR_SPLIT':
            continue
        elif inst.operation == 'MLIL_LOAD':
            continue
        elif inst.operation == 'MLIL_LOAD_STRUCT':
            continue
        elif inst.operation == 'MLIL_STORE':
            continue
        elif inst.operation == 'MLIL_STORE_STRUCT':
            continue
        elif inst.operation == 'MLIL_VAR':
            continue
        elif inst.operation == 'MLIL_VAR_ALIASED':
            continue
        elif inst.operation == 'MLIL_VAR_ALIASED_FIELD':
            continue
        elif inst.operation == 'MLIL_VAR_FIELD':
            continue
        elif inst.operation == 'MLIL_VAR_SPLIT':
            continue
        elif inst.operation == 'MLIL_VAR_PHI':
            continue
        elif inst.operation == 'MLIL_MEM_PHI':
            continue
        elif inst.operation == 'MLIL_ADDRESS_OF':
            continue
        elif inst.operation == 'MLIL_ADDRESS_OF_FIELD':
            continue
        elif inst.operation == 'MLIL_CONST':
            continue
        elif inst.operation == 'MLIL_CONST_DATA':
            continue
        elif inst.operation == 'MLIL_CONST_PTR':
            continue
        elif inst.operation == 'MLIL_EXTERN_PTR':
            continue
        elif inst.operation == 'MLIL_FLOAT_CONST':
            continue
        elif inst.operation == 'MLIL_IMPORT':
            continue
        elif inst.operation == 'MLIL_LOW_PART':
            continue
        elif inst.operation == 'MLIL_ADD':
            continue
        elif inst.operation == 'MLIL_ADC':
            continue
        elif inst.operation == 'MLIL_SUB':
            continue
        elif inst.operation == 'MLIL_SBB':
            continue
        elif inst.operation == 'MLIL_AND':
            continue
        elif inst.operation == 'MLIL_OR':
            continue
        elif inst.operation == 'MLIL_XOR':
            continue
        elif inst.operation == 'MLIL_LSL':
            continue
        elif inst.operation == 'MLIL_LSR':
            continue
        elif inst.operation == 'MLIL_ASR':
            continue
        elif inst.operation == 'MLIL_ROL':
            continue
        elif inst.operation == 'MLIL_RLC':
            continue
        elif inst.operation == 'MLIL_ROR':
            continue
        elif inst.operation == 'MLIL_RRC':
            continue
        elif inst.operation == 'MLIL_MUL':
            continue
        elif inst.operation == 'MLIL_MULU_DP':
            continue
        elif inst.operation == 'MLIL_MULS_DP':
            continue
        elif inst.operation == 'MLIL_DIVU':
            continue
        elif inst.operation == 'MLIL_DIVU_DP':
            continue
        elif inst.operation == 'MLIL_DIVS':
            continue
        elif inst.operation == 'MLIL_DIVS_DP':
            continue
        elif inst.operation == 'MLIL_MODU':
            continue
        elif inst.operation == 'MLIL_MODU_DP':
            continue
        elif inst.operation == 'MLIL_MODS':
            continue
        elif inst.operation == 'MLIL_MODS_DP':
            continue
        elif inst.operation == 'MLIL_NEG':
            continue
        elif inst.operation == 'MLIL_NOT':
            continue
        elif inst.operation == 'MLIL_FADD':
            continue
        elif inst.operation == 'MLIL_FSUB':
            continue
        elif inst.operation == 'MLIL_FMUL':
            continue
        elif inst.operation == 'MLIL_FDIV':
            continue
        elif inst.operation == 'MLIL_FSQRT':
            continue
        elif inst.operation == 'MLIL_FNEG':
            continue
        elif inst.operation == 'MLIL_FABS':
            continue
        elif inst.operation == 'MLIL_FLOAT_TO_INT':
            continue
        elif inst.operation == 'MLIL_INT_TO_FLOAT':
            continue
        elif inst.operation == 'MLIL_FLOAT_CONV':
            continue
        elif inst.operation == 'MLIL_ROUND_TO_INT':
            continue
        elif inst.operation == 'MLIL_FLOOR':
            continue
        elif inst.operation == 'MLIL_CEIL':
            continue
        elif inst.operation == 'MLIL_FTRUNC':
            continue
        elif inst.operation == 'MLIL_SX':
            continue
        elif inst.operation == 'MLIL_ZX':
            continue
        elif inst.operation == 'MLIL_ADD_OVERFLOW':
            continue
        elif inst.operation == 'MLIL_BOOL_TO_INT':
            continue
