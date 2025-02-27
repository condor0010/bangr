from binaryninja import MediumLevelILOperation

class MLILOpInfo():
    def __init__(self, taint_type, get_srcs, get_dests=None, get_important=None):
        self.taint_type = taint_type
        self.get_srcs = get_srcs
        self.get_dests = get_dests
        self.get_important = get_important



# TODO: All of the tuple elements below are special cases I don't know how to account for yet.
# We need to figure out how to turn them into a SSA vars that we can look up in our taint map.
# TODO: Constants currently return their associated constant. Need to figure out how to return
# constant info properly, or at least handle it.
op_map = {
    MediumLevelILOperation.MLIL_SET_VAR:
        MLILOpInfo('o', lambda operation: [op_map[operation.src]], get_dests=lambda operation: [op_map[operation.dest]]),
    MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
        MLILOpInfo('o', lambda operation: [op_map[operation.src]], get_dests=lambda operation: [op_map[operation.prev]]),
    MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD:
        MLILOpInfo('o', lambda operation: [op_map[operation.src]], get_dests=lambda operation: [(operation.prev,operation.offset)]), # TODO: how will this show up in our ssa var map?
    MediumLevelILOperation.MLIL_SET_VAR_FIELD:
        MLILOpInfo('o', lambda operation: [operation.src], get_dests=lambda operation: [(operation.dest,operation.offset)]),
    MediumLevelILOperation.MLIL_SET_VAR_SPLIT:
        MLILOpInfo('o', lambda operation: [operation.src], get_dests=lambda operation: [operation.high,operation.low]),
    MediumLevelILOperation.MLIL_LOAD:
        MLILOpInfo('a', lambda operation: [(operation.src,operation.size)]), # TODO: how will this show up in our ssa var map?
    MediumLevelILOperation.MLIL_LOAD_STRUCT:
        MLILOpInfo('a', lambda operation: [(operation.src,operation.offset)]), # TODO: how will this show up in our ssa var map?
    MediumLevelILOperation.MLIL_STORE:
        MLILOpInfo('o', lambda operation: [(operation.src,operation.size)], get_dests=lambda operation: [operation.dest,operation.size]),
    MediumLevelILOperation.MLIL_STORE_STRUCT:
        MLILOpInfo('o', lambda operation: [operation.src], get_dests=lambda operation: [(operation.dest,operation.offset,operation.size)]), # TODO: how will this show up in our ssa var map?
    MediumLevelILOperation.MLIL_VAR:
        MLILOpInfo('a',lambda operation: [operation.src]),
    MediumLevelILOperation.MLIL_VAR_ALIASED:
        MLILOpInfo('a',lambda operation: [operation.src]), # TODO: verify this works the same as MLIL_VAR. Docs say "A variable expression src that is known to have other variables pointing to the same destination"
    MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD:
        MLILOpInfo('a',lambda operation: None), # not documented
    MediumLevelILOperation.MLIL_VAR_FIELD:
        MLILOpInfo('a',lambda operation: [(operation.src,operation.offset)]),
    MediumLevelILOperation.MLIL_VAR_SPLIT:
        MLILOpInfo('a', lambda operation: [(operation.high,operation.low)]), # TODO: how will src show up in ssa var map?
    MediumLevelILOperation.MLIL_VAR_PHI:
        MLILOpInfo('p', lambda operation: operation.src, get_dests=lambda operation: [operation.dest]), # only 
    MediumLevelILOperation.MLIL_MEM_PHI:
        MLILOpInfo('p', lambda operation: operation.src_memory, get_dests=lambda operation: [operation.dest_memory]), # only returns numbers, for 'mem#x' vars where x is the generation of the mem var
    MediumLevelILOperation.MLIL_ADDRESS_OF:
        MLILOpInfo('a', lambda operation: [operation.src]),
    MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD:
        MLILOpInfo('a', lambda operation: [(operation.address,operation.offset)]),  # TODO: how will src show up?
    MediumLevelILOperation.MLIL_CONST:
        MLILOpInfo('a', lambda operation: [operation.constant]),  # do we just want to return None in the case of a constant?
    MediumLevelILOperation.MLIL_CONST_DATA:
        MLILOpInfo('a', lambda operation: [operation.constant]),
    MediumLevelILOperation.MLIL_CONST_PTR:
        MLILOpInfo('a', lambda operation: [operation.constant]),
    MediumLevelILOperation.MLIL_EXTERN_PTR:
        MLILOpInfo('a', lambda operation: [(operation.constant,operation.symbol)]),  # TODO: yet another special case
    MediumLevelILOperation.MLIL_FLOAT_CONST:
        MLILOpInfo('a', lambda operation: [operation.constant]),
    MediumLevelILOperation.MLIL_IMPORT:
        MLILOpInfo('a', lambda operation: [operation.constant]),
    MediumLevelILOperation.MLIL_LOW_PART:
        MLILOpInfo('a', lambda operation: [(operation.src,operation.size)]),  # TODO: another special case
    MediumLevelILOperation.MLIL_ADD:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_ADC:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right], get_important=lambda operation: [operation.carry]),
    MediumLevelILOperation.MLIL_SUB:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_SBB:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right], get_important=lambda operation: [operation.carry]),
    MediumLevelILOperation.MLIL_AND:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_OR:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_XOR:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_LSL:
        MLILOpInfo('i', lambda operation: [operation.left], get_important=lambda operation: [operation.right]),
    MediumLevelILOperation.MLIL_LSR:
        MLILOpInfo('i', lambda operation: [operation.left], get_important=lambda operation: [operation.right]),
    MediumLevelILOperation.MLIL_ASR:
        MLILOpInfo('i', lambda operation: [operation.left], get_important=lambda operation: [operation.right]),
    MediumLevelILOperation.MLIL_ROL:
        MLILOpInfo('i', lambda operation: [operation.left], get_important=lambda operation: [operation.right]),
    MediumLevelILOperation.MLIL_RLC:
        MLILOpInfo('i', lambda operation: [operation.left], get_important=lambda operation: [operation.right,operation.carry]),
    MediumLevelILOperation.MLIL_ROR:
        MLILOpInfo('i', lambda operation: [operation.left], get_important=lambda operation: [operation.right]),
    MediumLevelILOperation.MLIL_RRC:
        MLILOpInfo('i', lambda operation: [operation.left], get_important=lambda operation: [operation.right,operation.carry]),
    MediumLevelILOperation.MLIL_MUL:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_MULU_DP:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_MULS_DP:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_DIVU:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_DIVU_DP:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_DIVS:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_DIVS_DP:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_MODU:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_MODU_DP:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_MODS:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_MODS_DP:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_NEG:
        MLILOpInfo('o', lambda operation: [operation.src]),
    MediumLevelILOperation.MLIL_NOT:
        MLILOpInfo('o', lambda operation: [operation.src]),
    MediumLevelILOperation.MLIL_FADD:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_FSUB:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_FMUL:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_FDIV:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_FSQRT:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),
    MediumLevelILOperation.MLIL_FNEG:
        MLILOpInfo('o', lambda operation: [operation.src]),
    MediumLevelILOperation.MLIL_FABS:
        MLILOpInfo('o', lambda operation: [operation.src]),
    MediumLevelILOperation.MLIL_FLOAT_TO_INT:
        MLILOpInfo('o', lambda operation: [operation.src]),
    MediumLevelILOperation.MLIL_INT_TO_FLOAT:
        MLILOpInfo('o', lambda operation: [operation.src]),
    MediumLevelILOperation.MLIL_FLOAT_CONV:
        MLILOpInfo('o', lambda operation: [operation.src]),
    MediumLevelILOperation.MLIL_ROUND_TO_INT:
        MLILOpInfo('o', lambda operation: [operation.src]),
    MediumLevelILOperation.MLIL_FLOOR:
        MLILOpInfo('i', lambda operation: [operation.src]),
    MediumLevelILOperation.MLIL_CEIL:
        MLILOpInfo('i', lambda operation: [operation.src]),
    MediumLevelILOperation.MLIL_FTRUNC:
        MLILOpInfo('i', lambda operation: [operation.src]),
    MediumLevelILOperation.MLIL_SX:
        MLILOpInfo('o', lambda operation: [operation.src]),
    MediumLevelILOperation.MLIL_ZX:
        MLILOpInfo('o', lambda operation: [operation.src]),
    MediumLevelILOperation.MLIL_ADD_OVERFLOW:
        MLILOpInfo('i', lambda operation: [operation.left,operation.right]),  # TODO: this might be incorrect, could have undocumented overflow property, verify in binaja
    MediumLevelILOperation.MLIL_BOOL_TO_INT:
        MLILOpInfo('i', lambda operation: [operation.src])
}
