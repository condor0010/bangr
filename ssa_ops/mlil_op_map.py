from binaryninja import MediumLevelILOperation
from binaryninja.mediumlevelil import SSAVariable, MediumLevelILConst, MediumLevelILAdd, MediumLevelILConstPtr, MediumLevelILConstData, MediumLevelILVarSsa

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

class Var:
    def __init__(self, var_obj, offset=0, size=None):
        self.ssa_var = ssa_var
        self.offset = offset
        self.size = size

    def isPtr(self):
        return False

class ImmVar(Var):
    def __init__(self, ssa_var=None, offset=None, size=None):
        super().__init__(ssa_var, offset, size)

class PtrVar(Var):
    def __init__(self, ssa_var=None, offset=None, size=None, const=None):
        super().__init__(ssa_var, offset, size)
        self.const=const

class Token:
    def __init__(self, var_obj=None):
        self.var_obj = var_obj
        self.is_const = False
        self.is_ptr = False
        self.is_var = False

class DestToken(Token):
    def __init__(self, var_obj=None, offset=None, size=None):
        super().__init__(var_obj,const,offset,size)
        self._is_valid()

class SrcToken(Token):
    def __init__(self, var_obj, delta=0, _is_const=False):
        super().__init__(var_obj,delta)
        self.const=_is_const
        isValid()

class Const(SrcToken):
    def __init__(self, const):
        super().__init__(var_obj=const)
        self.is_const = True

class VarKey():
    def __init__(self, var, size=8, offset=0): # size should be size of architecture word
        self.var = var
        # could be SSAVariable, MediumLevelILConst, or VarKey
        #assert isinstance(var, SSAVariable)
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
    if isinstance(mlil, MediumLevelILConst):
        return [(VarKey(mlil), -1)]
    dict_value = op_map.get(mlil.operation, mlil.operation.name)
    if isinstance(dict_value, str):
        return [(mlil.operation.name, delta)]
    #print(dict_value)
    return dict_value.get_srcs(mlil, delta)

def loadLookup(mlil, delta, size):
    if isinstance(mlil, MediumLevelILVarSsa):
        return [(VarKey(mlil.src, offset=0, size=size), delta)]
    if isinstance(mlil, MediumLevelILConst) or isinstance(mlil, MediumLevelILConstPtr) or isinstance(mlil, MediumLevelILConstData):
        return [(VarKey(mlil, offset=0, size=size), -1)]
    # THIS MIGHT NEED SOME WORK, what if load doesn't only have Add as potential op?
    if isinstance(mlil, MediumLevelILAdd):
        #op_info = op_map.get(mlil)
        #srcs = op_info.get_srcs(mlil)
        return [(VarKey(mlil.left, offset=mlil.right, size=size), delta)]
    print(f'Unnaccounted for type: {type(mlil)}')
    assert False

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
# TODO: Account for special case
    MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
        MLILOpInfo(
            'o',
            lambda mlil, delta: doLookup(mlil.src,delta),
            get_dests=lambda mlil: [op_map[mlil.prev]]
        ),
# Prob when something like `var_c#0:0.d # mem#<x> -> mem#<x+1>` is on LHS
#    MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD:
#        MLILOpInfo(
#            'o',
#            lambda mlil, delta: doLookup(mlil.src),
#            get_dests=lambda mlil: [VarKey(mlil.src, size=mlil.size, offset=mlil.offset)]
#        ),
# the below likely looks like `__return_addr#0:0.d` on LHS
    MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD:
        MLILOpInfo(
            'o',
            lambda mlil, delta: doLookup(mlil.src, delta),
            get_dests=lambda mlil: [VarKey(mlil.src, size=mlil.size, offset=mlil.offset)]
        ),
    MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA:
        MLILOpInfo(
            'o',
            lambda mlil, delta: doLookup(mlil.src, delta),
            get_dests=lambda mlil: [VarKey(mlil.high), VarKey(mlil.low)]
        ),
# src could just be const or ssa_var, but could also be an MLIL_ADD
    MediumLevelILOperation.MLIL_LOAD_SSA:
        MLILOpInfo(
            'a',
            # can be const, ssa var, or either with an offset via MLIL_ADD
            lambda mlil, delta: loadLookup(mlil.src, delta, mlil.size)
        ),
    MediumLevelILOperation.MLIL_LOAD_STRUCT_SSA:
        MLILOpInfo(
            'a',
            lambda mlil, delta: [(VarKey(mlil.src, size=mlil.size, offset=mlil.offset), delta)]
        ),
# dest could just be const or ssa_var, but could also be an MLIL_ADD
    MediumLevelILOperation.MLIL_STORE_SSA:
        MLILOpInfo(
            'o',
            lambda mlil, delta: doLookup(mlil.src, delta, mlil.size),
            get_dests=lambda mlil: loadLookup(mlil.dest, delta, mlil.size)
        ),
    MediumLevelILOperation.MLIL_STORE_STRUCT_SSA:
        MLILOpInfo(
            'o',
            lambda mlil, delta: doLookup(mlil.src, delta),
            get_dests=lambda mlil: [VarKey(mlil.dest, size=mlil.size, offset=mlil.offset)]
            #get_dests=lambda mlil: loadLookup(mlil.mlil, delta, mlil.size)
        ),
    MediumLevelILOperation.MLIL_VAR_SSA:
        MLILOpInfo(
            'a',
            lambda mlil, delta: [(VarKey(mlil.src, size=mlil.size),delta)]
        ),
    # TODO: This is a special case, whatever this is set equal to will have the same
    #       taint entry as this
    MediumLevelILOperation.MLIL_VAR_ALIASED:
        MLILOpInfo(
            'a',  # technically also oto
            lambda mlil, delta: [(VarKey(mlil.src, size=mlil.size), delta)]
        ),
# TODO: Verify, prob looks something like `var_c#0:0.d @ mem<x> -> mem<x+1>`
#    MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD:
#        MLILOpInfo(
#            'a',
#            lambda mlil: None
#        ),
# TODO: Account for if mlil.src is not an ssa variable
#       Looks like `__return_addr#0:0.d`) where the second zero is the offset (i think) and the d ofc is the size
    MediumLevelILOperation.MLIL_VAR_SSA_FIELD:
        MLILOpInfo(
            'a',
            lambda mlil, delta: [(VarKey(mlil.src, size=mlil.size, offset=mlil.offset),delta)]
        ),
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
# TODO: account for MEM_PHI
#    MediumLevelILOperation.MLIL_MEM_PHI:
#        MLILOpInfo('p', lambda mlil: mlil.src_memory, get_dests=lambda mlil: [mlil.dest_memory]), # only returns numbers, for 'mem#x' vars where x is the generation of the mem var
# TODO: account for ADDRESS_OF operations, we dont control value directly,
#       instead we control memory pointed to by the value
#       Also, i dont think they qualify as atomic
# TODO: ADDRESS_OF operations are special cases where a var could be
# manipulated via means of this new pointer that's generated
    MediumLevelILOperation.MLIL_ADDRESS_OF:
        MLILOpInfo(
            'a',
            #TODO src could be of type `binaryninja.variable.Variable`
            lambda mlil, delta: [(VarKey(mlil.src), delta)] # ensure size is default size of pointer
        ),
# TODO: This will be special case where addr of field is gotten, so field could be
# referenced via means of this new pointer that's generated
#    MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD:
#        MLILOpInfo(
#            'a',
#            lambda mlil, delta: [(mlil.address,mlil.offset)]
#        ),
    MediumLevelILOperation.MLIL_CONST:
        MLILOpInfo(
            'a',
            lambda mlil, delta: [(VarKey(mlil.constant, size=mlil.size),-1)]
        ),
    MediumLevelILOperation.MLIL_CONST_DATA:
        MLILOpInfo(
            'a',
            lambda mlil, delta: [(VarKey(mlil.constant, size=mlil.size),-1)]
        ),
    MediumLevelILOperation.MLIL_CONST_PTR:
        MLILOpInfo(
            'a',
            lambda mlil, delta: [(VarKey(mlil.constant, size=mlil.size),-1)]
        ),
# TODO: Special case, how do we treat it?
#    MediumLevelILOperation.MLIL_EXTERN_PTR:
#        MLILOpInfo(
#            'a',
#            lambda mlil, delta: [(mlil.constant,mlil.symbol)]
#        ),
    MediumLevelILOperation.MLIL_FLOAT_CONST:
        MLILOpInfo(
            'a',
            lambda mlil, delta: [(VarKey(mlil.constant, size=mlil.size),-1)]
        ),
    MediumLevelILOperation.MLIL_IMPORT:
        MLILOpInfo(
           'a',
           lambda mlil, delta: [(VarKey(mlil.constant, size=mlil.size),0)]
        ),
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
