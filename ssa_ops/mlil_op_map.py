from binaryninja import MediumLevelILOperation
from binaryninja.mediumlevelil import SSAVariable, MediumLevelILConst, MediumLevelILAdd, MediumLevelILConstPtr, MediumLevelILConstData, MediumLevelILVarSsa, MediumLevelILStoreSsa, MediumLevelILImport, MediumLevelILSub

# default addr size. should be overwritten once binary
# view is opened.
ADDR_SIZE = None



class MLILOpInfo():
    # Note that nothing is done with `get_important`, it just denotes important
    # info that can be used by z3.
    def __init__(self, taint_type, get_srcs, get_dests=None, get_important=None):
        self.taint_type = taint_type
        self.get_srcs = get_srcs
        #if self.taint_type == 'a':
        #    assert get_dests is None
            #self.get_dests = get_srcs  # might be unnecessary bc ssa dest is always directly available from parent op
        #else:
        self.get_dests = get_dests
        self.get_important = get_important

# TODO: Size MUST be specified in initialization
class VarKey():
    def __init__(self, var, size=ADDR_SIZE, offset=0, offset_sign='+'):
        self.var = var
        # could be SSAVariable, MediumLevelILConst, or VarKey
        #assert isinstance(var, SSAVariable)
        self.size = size
        self.offset = offset
        self.offset_sign = offset_sign
        self.var_only = True
        if self.offset is not None:
            assert self.size is not None
            self.var_only = False
        else:
            assert self.size is None

    # TODO
    # table will be at least 2 layers: first is the var it affects,
    # next is the part of the var it affects
    def get_key(self):
        return None

# represents a value that must be looked up
# is a VarKey
class Element:
    def __init__(self, src):
        return None

    def eval(self):
        return get_taint(self.src)

# represent an operation that directly transfers taint
class OneToOne:
    def __init__(self, src):
        self.src = src
        return None
    
    def eval(self):
        return self.src.eval()

# represents an operation that will select the highest taint from one or
# more sources, then decrement it.
class Inherited:
    def __init__(self, srcs):
        self.srcs = srcs
        return None

    def eval(self):
        # reminder that the lower the number the higher the taint
        max_taint = self.srcs[0].eval()
        for i in range(1, len(self.srcs)):
            taint = s.eval()
            if taint < max_taint:
                max_taint = taint
        return max_taint + 1

def lookupSrcs(mlil, delta):
    if isinstance(mlil, SSAVariable):
        return [(VarKey(mlil), delta)]
    if isinstance(mlil, MediumLevelILConst):
        return [(VarKey(mlil), -1)]
    dict_value = op_map.get(mlil.operation, mlil.operation.name)
    if isinstance(dict_value, str) or dict_value is None:
        return [(mlil.operation.name, delta)]
    print(mlil.operation.name)
    return dict_value.get_srcs(mlil, delta)

def srcLoadLookup(mlil, delta, size):
    if isinstance(mlil, MediumLevelILVarSsa):
        return [(VarKey(mlil.src, offset=0, size=size), delta)]
    if isinstance(mlil, MediumLevelILConstData):
        const_data = mlil.const_data
        return [(VarKey(const_data.value, offset=const_data.offset, size=const_data.size), -1)]
    if isinstance(mlil, MediumLevelILConst) or isinstance(mlil, MediumLevelILConstPtr) or isinstance(mlil, MediumLevelILImport):
        return [(VarKey(mlil, offset=0, size=size), -1)]
    # THIS MIGHT NEED SOME WORK, what if load doesn't only have Add as potential op?
    if isinstance(mlil, MediumLevelILAdd):
        #op_info = op_map.get(mlil)
        #srcs = op_info.get_srcs(mlil)
        return [(VarKey(mlil.left, offset=mlil.right, size=size), delta)]
    if isinstance(next_mlil, MediumLevelILSub):
        return [VarKey(next_mlil.left, offset=next_mlil.right, offset_sign='-', size=mlil.size)]
    print(f'Unnaccounted for type at {hex(mlil.address)}: {mlil.operation.name}')
    assert False


def lookupDest(mlil):
    if isinstance(mlil, MediumLevelILStoreSsa):
        # TODO: this is gross
        next_mlil = mlil.dest
        if isinstance(next_mlil, MediumLevelILAdd):
            return [VarKey(next_mlil.left, offset=next_mlil.right, size=mlil.size)]
        if isinstance(next_mlil, MediumLevelILSub):
            return [VarKey(next_mlil.left, offset=next_mlil.right, offset_sign='-', size=mlil.size)]
        if isinstance(mlil, MediumLevelILConstData):
            const_data = mlil.const_data
            return [VarKey(const_data.value, offset=const_data.offset, size=const_data.size)]
        if isinstance(next_mlil, MediumLevelILConst) or isinstance(next_mlil, MediumLevelILConstPtr) or isinstance(next_mlil, MediumLevelILImport):
            return [VarKey(next_mlil, offset=0, size=next_mlil.size)]
        if isinstance(next_mlil, MediumLevelILVarSsa):
            return [VarKey(next_mlil.src, offset=0, size=next_mlil.size)]
        print(f'Unaccounted for type in StoreSsa Dest at {hex(mlil.address)}: {next_mlil.operation.name}')
        assert False
    dict_value = op_map.get(mlil.operation, mlil.operation.name)
    if isinstance(dict_value, str) or dict_value is None:
        return [mlil.operation.name]
    print(mlil.operation.name)
    return dict_value.get_dests(mlil)

def destStoreLookup(mlil, size):
    if isinstance(next_mlil, MediumLevelILAdd):
        return [VarKey(next_mlil.left, offset=next_mlil.right, size=mlil.size)]
    if isinstance(next_mlil, MediumLevelILSub):
        return [VarKey(next_mlil.left, offset=next_mlil.right, offset_sign='-', size=mlil.size)]
    if isinstance(mlil, MediumLevelILConstData):
        const_data = mlil.const_data
        return [VarKey(const_data.value, offset=const_data.offset, size=const_data.size)]
    if isinstance(next_mlil, MediumLevelILConst) or isinstance(next_mlil, MediumLevelILConstPtr) or isinstance(next_mlil, MediumLevelILImport):
        return [VarKey(next_mlil, offset=0, size=next_mlil.size)]
    if isinstance(next_mlil, MediumLevelILVarSsa):
        return [VarKey(next_mlil.src, offset=0, size=next_mlil.size)]
    print(f'Unaccounted for type in StoreSsa Dest at {hex(mlil.address)}: {next_mlil.operation.name}')
    assert False

# TODO: All of the tuple elements below are special cases I don't know how to account for yet.
# We need to figure out how to turn them into a SSA vars that we can look up in our taint map.
# TODO: Constants currently return their associated constant. Need to figure out how to return
# constant info properly, or at least handle it.
# TODO: create get_dests for every atomic operation

# lookup: op_map[mlil.operation].get_srcs(mlil.attr, delta+1)
# retval for sources is an array of tuples where the first in the tuple is a VarKey, while the second is the delta.
op_map = {
    MediumLevelILOperation.MLIL_SET_VAR_SSA:
        MLILOpInfo(
            'o',
            lambda mlil, delta: lookupSrcs(mlil.src, delta),
            get_dests=lambda mlil: [VarKey(mlil.dest)]
        ),
# TODO: Account for special case
    MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
        MLILOpInfo(
            'o',
            lambda mlil, delta: lookupSrcs(mlil.src,delta),
            get_dests=lambda mlil: [VarKey(mlil.dest)]
        ),
# Prob when something like `var_c#0:0.d # mem#<x> -> mem#<x+1>` is on LHS
    MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD:
        MLILOpInfo(
            'o',
            lambda mlil, delta: lookupSrcs(mlil.src, delta),
            get_dests=lambda mlil: [VarKey(mlil.src, size=mlil.size, offset=mlil.offset)]
        ),
# the below likely looks like `__return_addr#0:0.d` on LHS
    MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD:
        MLILOpInfo(
            'o',
            lambda mlil, delta: lookupSrcs(mlil.src, delta),
            # could there be situation where dest is not an ssa var?
            get_dests=lambda mlil: [VarKey(mlil.dest, size=mlil.size, offset=mlil.offset)]
        ),
    MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA:
        MLILOpInfo(
            'o',
            lambda mlil, delta: lookupSrcs(mlil.src, delta),
            get_dests=lambda mlil: [VarKey(mlil.high), VarKey(mlil.low)]
        ),
# src could just be const or ssa_var, but could also be an MLIL_ADD
    MediumLevelILOperation.MLIL_LOAD_SSA:
        MLILOpInfo(
            'a',
            # can be const, ssa var, or either with an offset via MLIL_ADD
            lambda mlil, delta: srcLoadLookup(mlil.src, delta, mlil.size)
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
            lambda mlil, delta: lookupSrcs(mlil.src, delta, mlil.size),
            get_dests=lambda mlil: srcLoadLookup(mlil.dest, 0, mlil.size)
        ),
    MediumLevelILOperation.MLIL_STORE_STRUCT_SSA:
        MLILOpInfo(
            'o',
            lambda mlil, delta: lookupSrcs(mlil.src, delta),
            get_dests=lambda mlil: [VarKey(mlil.dest, size=mlil.size, offset=mlil.offset)]
            #get_dests=lambda mlil: srcLoadLookup(mlil.mlil, delta, mlil.size)
        ),
    MediumLevelILOperation.MLIL_VAR_SSA:
        MLILOpInfo(
            'a',
            lambda mlil, delta: [(VarKey(mlil.src, size=mlil.size),delta)],
            get_dests=lambda mlil: [VarKey(mlil.src, size=mlil.size)]
        ),
    # TODO: This is a special case, whatever this is set equal to will have the same
    #       taint entry as this
    MediumLevelILOperation.MLIL_VAR_ALIASED:
        MLILOpInfo(
            'a',  # technically also oto
            lambda mlil, delta: [(VarKey(mlil.src, size=mlil.size), delta)]
        ),
# TODO: Verify, prob looks something like `var_c#0:0.d @ mem<x> -> mem<x+1>`
    MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD:
        MLILOpInfo(
            'a',
            lambda mlil, delta: [(VarKey(mlil.src, size=mlil.size, offset=mlil.offset), delta)]
        ),
# TODO: Account for if mlil.src is not an ssa variable
#       Looks like `__return_addr#0:0.d`) where the second zero is the offset (i think) and the d ofc is the size
# Could also look like this `2809 @ 001491a3  i_17#2 = i_16#65.r13d` where i_16 is held in r13, but we're only accessing
# bottom 4 bytes. Might not matter if we do field offsetting correctly.
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
    MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD:
        MLILOpInfo(
            'a',
            lambda mlil, delta: [(mlil.address,mlil.offset)]
        ),
    MediumLevelILOperation.MLIL_CONST:
        MLILOpInfo(
            'a',
            lambda mlil, delta: [(VarKey(mlil.constant, size=mlil.size),-1)]
        ),
    MediumLevelILOperation.MLIL_CONST_DATA:
        MLILOpInfo(
            'a',
            lambda mlil, delta: [(VarKey(mlil.constant_data.value, offset=mlil.constant_data.offset, size=mlil.constant_data.size),-1)]
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
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_ADC:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1),
            get_important=lambda mlil: [mlil.carry] # TODO: not doing anything with this atm
        ),
    MediumLevelILOperation.MLIL_SUB:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_SBB:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1),
            get_important=lambda mlil: [mlil.carry]
        ),
    MediumLevelILOperation.MLIL_AND:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_OR:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_XOR:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_LSL:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1),
            get_important=lambda mlil: [lookupSrcs(mlil.right)]
        ),
    MediumLevelILOperation.MLIL_LSR:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1),
            get_important=lambda mlil: [mlil.right] # TODO: not doing anything with this atm
        ),
    MediumLevelILOperation.MLIL_ASR:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1),
            get_important=lambda mlil: [mlil.right]
        ),
    MediumLevelILOperation.MLIL_ROL:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1),
            get_important=lambda mlil: [mlil.right]
        ),
    MediumLevelILOperation.MLIL_RLC:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1),
            get_important=lambda mlil: [mlil.right,mlil.carry]
        ),
    MediumLevelILOperation.MLIL_ROR:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1),
            get_important=lambda mlil: [mlil.right]
        ),
    MediumLevelILOperation.MLIL_RRC:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1),
            get_important=lambda mlil: [mlil.right,mlil.carry]
        ),
    MediumLevelILOperation.MLIL_MUL:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_MULU_DP:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_MULS_DP:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_DIVU:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_DIVU_DP:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_DIVS:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_DIVS_DP:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1) 
        ),
    MediumLevelILOperation.MLIL_MODU:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_MODU_DP:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_MODS:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_MODS_DP:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_NEG:
        MLILOpInfo(
            'o',
            lambda mlil, delta: lookupSrcs(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_NOT:
        MLILOpInfo(
            'o',
            lambda mlil, delta: lookupSrcs(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_FADD:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_FSUB:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1),
            get_dests=lambda mlil: [VarKey(mlil.left, size=mlil.size)]
        ),
    MediumLevelILOperation.MLIL_FMUL:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_FDIV:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_FSQRT:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),
    MediumLevelILOperation.MLIL_FNEG:
        MLILOpInfo(
            'o',
            lambda mlil, delta: lookupSrcs(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_FABS:
        MLILOpInfo(
            'o',
            lambda mlil, delta: lookupSrcs(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_FLOAT_TO_INT:
        MLILOpInfo(
            'o',
            lambda mlil, delta: lookupSrcs(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_INT_TO_FLOAT:
        MLILOpInfo(
            'o',
            lambda mlil, delta: lookupSrcs(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_FLOAT_CONV:
        MLILOpInfo(
            'o',
            lambda mlil, delta: lookupSrcs(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_ROUND_TO_INT:
        MLILOpInfo(
            'o',
            lambda mlil, delta: lookupSrcs(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_FLOOR:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.src,delta+1)
        ),
    MediumLevelILOperation.MLIL_CEIL:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.src,delta+1)
        ),
    MediumLevelILOperation.MLIL_FTRUNC:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.src,delta+1)
        ),
    MediumLevelILOperation.MLIL_SX:
        MLILOpInfo(
            'o',
            lambda mlil, delta: lookupSrcs(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_ZX:
        MLILOpInfo(
            'o',
            lambda mlil, delta: lookupSrcs(mlil.src,delta)
        ),
    MediumLevelILOperation.MLIL_ADD_OVERFLOW:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.left,delta+1) + lookupSrcs(mlil.right,delta+1)
        ),  # TODO: this might be incorrect, could have undocumented overflow property, verify in binaja
    MediumLevelILOperation.MLIL_BOOL_TO_INT:
        MLILOpInfo(
            'i',
            lambda mlil, delta: lookupSrcs(mlil.src,delta+1)
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
