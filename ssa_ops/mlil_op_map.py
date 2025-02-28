from binaryninja import MediumLevelILOperation
from binaryninja.mediumlevelil import SSAVariable

class MLILOpInfo():
    def __init__(self, taint_type, get_srcs, get_dests=None, get_important=None):
        self.taint_type = taint_type
        self.get_srcs = get_srcs
        if self.taint_type == 'a':
            assert get_dests is None
            #self.get_dests = get_srcs  # might be unnecessary bc ssa dest is always directly available from parent op
        else:
            self.get_dests = get_dests
        self.get_important = get_important

class VarKey():
    def __init__(self, var, size=None, offset=None):
        self.var = var
        assert isinstance(var, SSAVariable)
        self.size = size
        self.offset = offset
        self.var_only = True
        if self.offset is not None:
            assert self.size is not None
            self.var_only = False
        else:
            assert self.size is None

    # TODO: create some sort of key based of the instance info for lookup
    # in our taint table
    def get_key(self):
        return None

def doLookup(mlil, delta):
    if isinstance(mlil, SSAVariable):
        return [(VarKey(mlil), delta)]
    dict_value = op_map.get(mlil.operation, mlil.operation.name)
    if isinstance(dict_value, str):
        return [(mlil.operation.name, delta)]
    return dict_value.get_srcs(mlil, delta)

# TODO: All of the tuple elements below are special cases I don't know how to account for yet.
# We need to figure out how to turn them into a SSA vars that we can look up in our taint map.
# TODO: Constants currently return their associated constant. Need to figure out how to return
# constant info properly, or at least handle it.
# lookup: op_map[mlil.operation].get_srcs(mlil.attr, delta+1)
# retval for sources is an array of tuples where the first in the tuple is a VarKey, while the second is the delta.
op_map = {
    MediumLevelILOperation.MLIL_SET_VAR_SSA:
        MLILOpInfo(
            'o',
            lambda mlil, delta: doLookup(mlil.src, delta),
            get_dests=lambda mlil: [VarKey(mlil.dest)]
        ),
#    MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
#        MLILOpInfo('o', lambda mlil: [op_map[mlil.src]], get_dests=lambda mlil: [op_map[mlil.prev]]),
#    MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD:
#        MLILOpInfo('o', lambda mlil: [op_map[mlil.src]], get_dests=lambda mlil: [(mlil.prev,mlil.offset)]),
    MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD:
        MLILOpInfo(
            'o',
            lambda mlil, delta: doLookup(mlil.src, delta),
            get_dests=lambda mlil: [VarKey(mlil.dest, size=0, offset=mlil.offset)]
        ),
    MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA:
        MLILOpInfo(
            'o',
            lambda mlil, delta: doLookup(mlil.src, delta),
            get_dests=lambda mlil: [VarKey(mlil.high), VarKey(mlil.low)]
        ),
# TODO: don't yet account for if mlil.src is not a variable
#    MediumLevelILOperation.MLIL_LOAD_SSA:
#        MLILOpInfo(
#            'a',
#            lambda mlil, delta: [(VarKey(mlil.src, size=mlil.size, offset=0),delta)]
#        ),
#    MediumLevelILOperation.MLIL_LOAD_STRUCT_SSA:
#        MLILOpInfo(
#            'a',
#            lambda mlil, delta: [(VarKey(mlil.src, size=0, offset=mlil.offset),delta)]
#        ),
#    MediumLevelILOperation.MLIL_STORE_SSA:
#        MLILOpInfo(
#            'o',
#            lambda mlil, delta: [(VarKey(mlil.src, size=mlil.size, offset=0),delta)],
#            get_dests=lambda mlil: [VarKey(mlil.dest, size=mlil.size, offset=0)]
#        ),
#    MediumLevelILOperation.MLIL_STORE_STRUCT_SSA:
#        MLILOpInfo(
#            'o',
#            lambda mlil, delta: doLookup(mlil.src, delta),
#            get_dests=lambda mlil: [VarKey(mlil.dest, size=mlil.size, offset=mlil.offset)]
#        ),
    MediumLevelILOperation.MLIL_VAR_SSA:
        MLILOpInfo(
            'a',
            lambda mlil, delta: [(VarKey(mlil.src),delta)]
        ),
# TODO: verify this works the same as MLIL_VAR. Docs say "A variable expression
#       src that is known to have other variables pointing to the same destination"
#    MediumLevelILOperation.MLIL_VAR_ALIASED:
#        MLILOpInfo('a',lambda mlil: [mlil.src]),
#    MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD:
#        MLILOpInfo('a',lambda mlil: None), # not documented
# TODO: Account for if mlil.src is not an ssa variable
#    MediumLevelILOperation.MLIL_VAR_SSA_FIELD:
#        MLILOpInfo(
#            'a',
#            lambda mlil, delta: [(VarKey(mlil.src, size=mlil.size, offset=mlil.offset),delta)]
#        ),
    MediumLevelILOperation.MLIL_VAR_SPLIT_SSA:
        MLILOpInfo(
            'a',
            lambda mlil, delta: [(VarKey(mlil.high),delta), (VarKey(mlil.low),delta)]
        ),
    MediumLevelILOperation.MLIL_VAR_PHI:
        MLILOpInfo(
            'p',
            lambda mlil, delta: map(lambda src: (VarKey(src),delta), mlil.src),
            get_dests=lambda mlil: [VarKey(mlil.dest)]
        ),
# TODO: account for the below
#    MediumLevelILOperation.MLIL_MEM_PHI:
#        MLILOpInfo('p', lambda mlil: mlil.src_memory, get_dests=lambda mlil: [mlil.dest_memory]), # only returns numbers, for 'mem#x' vars where x is the generation of the mem var
# TODO: account for ADDRESS_OF operations, we dont control value directly,
#       instead we control memory pointed to by the value
#       Also, i dont think they qualify as atomic
#    MediumLevelILOperation.MLIL_ADDRESS_OF:
#        MLILOpInfo(
#            'a',
#            lambda mlil, delta: [mlil.src]
#        ),
#    MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD:
#        MLILOpInfo(
#            'a',
#            lambda mlil, delta: [(mlil.address,mlil.offset)]
#        ),
# TODO: How do we account for constants?
#    MediumLevelILOperation.MLIL_CONST:
#        MLILOpInfo(
#            'a',
#            lambda mlil, delta: [mlil.constant]
#        ),  # do we just want to return None in the case of a constant?
#    MediumLevelILOperation.MLIL_CONST_DATA:
#        MLILOpInfo(
#            'a',
#            lambda mlil, delta: [mlil.constant]
#        ),
#    MediumLevelILOperation.MLIL_CONST_PTR:
#        MLILOpInfo(
#            'a',
#            lambda mlil, delta: [mlil.constant]
#        ),
#    MediumLevelILOperation.MLIL_EXTERN_PTR:
#        MLILOpInfo(
#            'a',
#            lambda mlil, delta: [(mlil.constant,mlil.symbol)]
#        ),  # TODO: yet another special case
#    MediumLevelILOperation.MLIL_FLOAT_CONST:
#        MLILOpInfo(
#            'a',
#            lambda mlil, delta: [mlil.constant]
#        ),
#    MediumLevelILOperation.MLIL_IMPORT:
#        MLILOpInfo(
#           'a',
#           lambda mlil, delta: [mlil.constant]
#        ),
    MediumLevelILOperation.MLIL_LOW_PART:
        MLILOpInfo(
           'a',
           lambda mlil, delta: [(VarKey(mlil.src, size=mlil.size, offset=0),delta)]
        ),
    MediumLevelILOperation.MLIL_ADD:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_ADC:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1),
            get_important=lambda mlil: [mlil.carry] # TODO: not doing anything with this atm
        ),
    MediumLevelILOperation.MLIL_SUB:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_SBB:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1),
            get_important=lambda mlil: [mlil.carry]
        ),
    MediumLevelILOperation.MLIL_AND:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_OR:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_XOR:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_LSL:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1),
            get_important=lambda mlil: [doLookup(mlil.right)]
        ),
    MediumLevelILOperation.MLIL_LSR:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1),
            get_important=lambda mlil: [mlil.right] # TODO: not doing anything with this atm
        ),
    MediumLevelILOperation.MLIL_ASR:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1),
            get_important=lambda mlil: [mlil.right]
        ),
    MediumLevelILOperation.MLIL_ROL:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1),
            get_important=lambda mlil: [mlil.right]
        ),
    MediumLevelILOperation.MLIL_RLC:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1),
            get_important=lambda mlil: [mlil.right,mlil.carry]
        ),
    MediumLevelILOperation.MLIL_ROR:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1),
            get_important=lambda mlil: [mlil.right]
        ),
    MediumLevelILOperation.MLIL_RRC:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1),
            get_important=lambda mlil: [mlil.right,mlil.carry]
        ),
    MediumLevelILOperation.MLIL_MUL:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_MULU_DP:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_MULS_DP:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_DIVU:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_DIVU_DP:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_DIVS:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_DIVS_DP:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1) 
        ),
    MediumLevelILOperation.MLIL_MODU:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_MODU_DP:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_MODS:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_MODS_DP:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_NEG:
        MLILOpInfo(
            'o',
            lambda mlil, delta: doLookup(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_NOT:
        MLILOpInfo(
            'o',
            lambda mlil, delta: doLookup(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_FADD:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_FSUB:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_FMUL:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_FDIV:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_FSQRT:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_FNEG:
        MLILOpInfo(
            'o',
            lambda mlil, delta: doLookup(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_FABS:
        MLILOpInfo(
            'o',
            lambda mlil, delta: doLookup(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_FLOAT_TO_INT:
        MLILOpInfo(
            'o',
            lambda mlil, delta: doLookup(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_INT_TO_FLOAT:
        MLILOpInfo(
            'o',
            lambda mlil, delta: doLookup(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_FLOAT_CONV:
        MLILOpInfo(
            'o',
            lambda mlil, delta: doLookup(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_ROUND_TO_INT:
        MLILOpInfo(
            'o',
            lambda mlil, delta: doLookup(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_FLOOR:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.src,delta+1)
        ),
    MediumLevelILOperation.MLIL_CEIL:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.src,delta+1)
        ),
    MediumLevelILOperation.MLIL_FTRUNC:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.src,delta+1)
        ),
    MediumLevelILOperation.MLIL_SX:
        MLILOpInfo(
            'o',
            lambda mlil, delta: doLookup(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_ZX:
        MLILOpInfo(
            'o',
            lambda mlil, delta: doLookup(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_ADD_OVERFLOW:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.left,delta+1) + doLookup(mlil.right,delta+1)
        ),  # TODO: this might be incorrect, could have undocumented overflow property, verify in binaja
    MediumLevelILOperation.MLIL_BOOL_TO_INT:
        MLILOpInfo(
            'i',
            lambda mlil, delta: doLookup(mlil.src,delta+1)
        )
}

# TODO: Add following SSA operations to op_map
# MLIL_CALL_OUTPUT_SSA
# MLIL_CALL_PARAM_SSA
# MLIL_CALL_SSA
# MLIL_CALL_UNTYPED_SSA
# MLIL_FREE_VAR_SLOT_SSA
# MLIL_INTRINSIC_SSA
# MLIL_MEMORY_INTRINSIC_OUTPUT_SSA
# MLIL_MEMORY_INTRINSIC_SSA
# MLIL_SYSCALL_SSA
# MLIL_SYSCALL_UNTYPED_SSA
# MLIL_TAILCALL_SSA
# MLIL_TAILCALL_UNTYPED_SSA
