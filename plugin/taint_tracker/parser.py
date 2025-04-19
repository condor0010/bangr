from binaryninja import MediumLevelILOperation
from binaryninja.mediumlevelil import SSAVariable, MediumLevelILConst, MediumLevelILAdd, MediumLevelILConstPtr, MediumLevelILConstData, MediumLevelILVarSsa, MediumLevelILStoreSsa, MediumLevelILImport, MediumLevelILSub
from global_vars import *
from tree import *

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

unknown_src_ops = {}
def lookupSrcs(mlil, size):
    if isinstance(mlil, SSAVariable):
        return VarKey(mlil, size)
    if isinstance(mlil, MediumLevelILConst):
        return VarKey(mlil, size)
    dict_value = op_map.get(mlil.operation, mlil.operation.name)
    # debugging
    if isinstance(dict_value, str) or dict_value is None:
        if mlil.operation.name in unknown_src_ops:
            unknown_src_ops[mlil.operation.name].add(mlil.address)
        else:
            unknown_src_ops[mlil.operation.name] = {mlil.address}
        return mlil.operation.name
    #print(mlil.operation.name)
    # continue recursive lookup
    return dict_value.get_srcs(mlil)

# must return VarKey
def srcLoadLookup(mlil, size, mem_version):
    if isinstance(mlil, MediumLevelILVarSsa):
        return VarKey(mlil.src, size, offset=0, is_deref=True, is_mem=True, mem_version=mem_version)
    # TODO: Check if this is necessary, will remove if not
    #if isinstance(mlil, MediumLevelILConstData):
    #    const_data = mlil.const_data
    #    return VarKey(const_data.value, size, offset=const_data.offset)
    if isinstance(mlil, MediumLevelILConstPtr) or isinstance(mlil, MediumLevelILImport):
        return VarKey(mlil, size, offset=0, is_deref=True, is_mem=True, mem_version=mem_version)
    if isinstance(mlil, MediumLevelILAdd):
        return interpretDerefOffset(mlil, size, '+', mem_version)
    if isinstance(next_mlil, MediumLevelILSub):
        return interpretDerefOffset(mlil, size, '-', mem_version)
    print(f'Unnaccounted for type at {hex(mlil.address)}: {mlil.operation.name}')
    assert False

def interpretDerefOffset(deref_op, size, sign, mem_version):
    if isinstance(deref_op.left, MediumLevelILConst):
        if isinstance(deref_op.right, MediumLevelILVarSsa):
            return VarKey(deref_op.right, size, offset=deref_op.left, is_deref=True, is_mem=True, mem_version=mem_version)
        elif isinstance(deref_op.right, MediumLevelILConstPtr) or isinstance(deref_op.right, MediumLevelILImport):
            return VarKey(deref_op.right, size, offset=deref_op.left, is_deref=True, is_mem=True, mem_version=mem_version)
    elif isinstance(deref_op.right, MediumLevelILConst):
        if isinstance(deref_op.left, MediumLevelILVarSsa):
            return VarKey(deref_op.left, size, offset=deref_op.right, is_deref=True, is_mem=True, mem_version=mem_version)
        elif isinstance(deref_op.left, MediumLevelILConstPtr) or isinstance(deref_op.left, MediumLevelILImport):
            return VarKey(deref_op.left, size, offset=deref_op.right, is_deref=True, is_mem=True, mem_version=mem_version)
    # is too complicated, turn into string of tokens for use as taint key
    token_string = ''.join(list(map(lambda t: str(t), deref_op.tokens)))
    return VarKey(token_string, size, is_deref=True, is_mem=True, mem_version=mem_version)

def lookupDest(mlil):
    dict_value = op_map.get(mlil.operation, mlil.operation.name)
    if isinstance(dict_value, str) or dict_value is None:
        return [mlil.operation.name]
    #print(mlil.operation.name)
    return dict_value.get_dests(mlil)

# lookup: op_map[mlil.operation].get_srcs(mlil.attr)
op_map = {
    MediumLevelILOperation.MLIL_SET_VAR_SSA:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size)),
            get_dests=lambda mlil: [VarKey(mlil.dest, mlil.size)]
        ),
# prev attr also exists for the dest, but when it's an ssa var it just
# tells you the previous version of the ssa var
    MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size)),
            get_dests=lambda mlil: [VarKey(mlil.dest, mlil.size, is_mem=True, mem_version=mlil.dest.version)]
        ),
# Prob when something like `var_c#0:0.d # mem#<x> -> mem#<x+1>` or `var_38.string @ mem#2 -> mem#3 = rax#1` is on LHS
# TODO: Prev ends up being important because the rest of that structure needs to be copied over
    MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size)),
            get_dests=lambda mlil: [VarKey(mlil.src, mlil.size, offset=mlil.offset, is_mem=True, mem_version=mlil.dest.version)]
        ),
# the below likely looks like `__return_addr#0:0.d` on LHS
    MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size)),
            get_dests=lambda mlil: [VarKey(mlil.dest, mlil.size, offset=mlil.offset, is_mem=True, mem_version=mlil.dest.version)]
        ),
    MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size)),
            get_dests=lambda mlil: [VarKey(mlil.high, mlil.size), VarKey(mlil.low, mlil.size)]
        ),
# src could just be const or ssa_var, but could also be an MLIL_ADD
    MediumLevelILOperation.MLIL_LOAD_SSA:
        MLILOpInfo(
            'a',
            # can be const, ssa var, or either with an offset via MLIL_ADD
            lambda mlil: srcLoadLookup(mlil.src, mlil.size, mlil.src_memory)
        ),
# TODO: have to set the memory stuff here too
    MediumLevelILOperation.MLIL_LOAD_STRUCT_SSA:
        MLILOpInfo(
            'a',
            lambda mlil: VarKey(mlil.src, mlil.size, offset=mlil.offset, is_deref=True, is_mem=True, mem_version=mlil.src_memory)
        ),
# dest could just be const or ssa_var, but could also be an MLIL_ADD
    MediumLevelILOperation.MLIL_STORE_SSA:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size)),
            get_dests=lambda mlil: [srcLoadLookup(mlil.dest, mlil.size, mlil.dest_memory)]
        ),
    MediumLevelILOperation.MLIL_STORE_STRUCT_SSA:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size)),
            get_dests=lambda mlil: [VarKey(mlil.dest, mlil.size, offset=mlil.offset)]
        ),
    MediumLevelILOperation.MLIL_VAR_SSA:
        MLILOpInfo(
            'a',
            lambda mlil: VarKey(mlil.src, mlil.size),
            get_dests=lambda mlil: [VarKey(mlil.src, mlil.size)]
        ),
    # TODO: This is a special case, whatever this is set equal to will have the same
    #       taint entry as this
    MediumLevelILOperation.MLIL_VAR_ALIASED:
        MLILOpInfo(
            'a',  # technically also oto
            lambda mlil: VarKey(mlil.src, mlil.size)
        ),
# TODO: Looks something like `var_c#0:0.d @ mem<x>` or `var_38.string @ mem#4`, might have to set
# `is_mem` and `mem_version` fields
    MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD:
        MLILOpInfo(
            'a',
            lambda mlil: VarKey(mlil.src, mlil.size, offset=mlil.offset, is_mem=True, mem_version=mlil.ssa_memory_version)
        ),
# TODO: Account for if mlil.src is not an ssa variable
#       Looks like `__return_addr#0:0.d`) where the second zero is the offset (i think) and the d ofc is the size
# Could also look like this `2809 @ 001491a3  i_17#2 = i_16#65.r13d` where i_16 is held in r13, but we're only accessing
# bottom 4 bytes. Might not matter if we do field offsetting correctly.
    MediumLevelILOperation.MLIL_VAR_SSA_FIELD:
        MLILOpInfo(
            'a',
            lambda mlil: VarKey(mlil.src, mlil.size, offset=mlil.offset)
        ),
# example: used in x86_64 division and modulus where 2 regs are affected with one op
    MediumLevelILOperation.MLIL_VAR_SPLIT_SSA:
        MLILOpInfo(
            'a',
            lambda mlil: Inherited(VarKey(mlil.high, mlil.size), (VarKey(mlil.low, mlil.size)))
        ),
    MediumLevelILOperation.MLIL_VAR_PHI:
        MLILOpInfo(
            'p',
            lambda mlil: list(map(lambda src: (VarKey(src, mlil.size)), mlil.src)),
            get_dests=lambda mlil: [VarKey(mlil.dest, mlil.size)]
        ),
# TODO: account for MEM_PHI
#    MediumLevelILOperation.MLIL_MEM_PHI:
#        MLILOpInfo('p', lambda mlil: mlil.src_memory, get_dests=lambda mlil: [mlil.dest_memory]), # only returns numbers, for 'mem#x' vars where x is the generation of the mem var
# TODO: account for ADDRESS_OF operations, we dont control value directly,
#       instead we control memory pointed to by the value
#       Also, i dont think they qualify as atomic
# TODO: ADDRESS_OF operations are special cases where a var could be
# manipulated via means of this new pointer that's generated
# NOTE: ADDRESS_OF ops will just be considered as consts for the time being
    MediumLevelILOperation.MLIL_ADDRESS_OF:
        MLILOpInfo(
            'a',
            #TODO src could be of type `binaryninja.variable.Variable`
            lambda mlil: VarKey(mlil.src, mlil.size, is_deref=True) # size technically comes to 0
        ),
# TODO: This will be special case where addr of field is gotten, so field could be
# referenced via means of this new pointer that's generated, find example
    MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD:
        MLILOpInfo(
            'a',
            lambda mlil: VarKey(mlil.src, mlil.size, mlil.offset, is_deref=True)
        ),
    MediumLevelILOperation.MLIL_CONST:
        MLILOpInfo(
            'a',
            lambda mlil: VarKey(mlil.constant, mlil.size)
        ),
    MediumLevelILOperation.MLIL_CONST_DATA:
        MLILOpInfo(
            'a',
            lambda mlil: VarKey(mlil.constant_data.value, mlil.constant_data.size, offset=mlil.constant_data.offset)
        ),
    MediumLevelILOperation.MLIL_CONST_PTR:
        MLILOpInfo(
            'a',
            lambda mlil: VarKey(mlil.constant, mlil.size)
        ),
# TODO: Special case, how do we treat the .symbol field
    MediumLevelILOperation.MLIL_EXTERN_PTR:
        MLILOpInfo(
            'a',
            lambda mlil: VarKey(mlil.constant, mlil.size) #[(mlil.constant,mlil.symbol)]
        ),
    MediumLevelILOperation.MLIL_FLOAT_CONST:
        MLILOpInfo(
            'a',
            lambda mlil: VarKey(mlil.constant, mlil.size)
        ),
    MediumLevelILOperation.MLIL_IMPORT:
        MLILOpInfo(
           'a',
           lambda mlil: VarKey(mlil.constant, mlil.size)
        ),
    # TODO: This can contain MLIL_ALIASED_VAR and likely other var types.
#    MediumLevelILOperation.MLIL_LOW_PART:
#        MLILOpInfo(
#           'a',
#           lambda mlil: VarKey(mlil.src, mlil.size, offset=0, is_mem=True, mem_version=mlil.src.ssa_memory_version)
#        ),
    MediumLevelILOperation.MLIL_ADD:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_ADC:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size)),
            get_important=lambda mlil: [mlil.carry] # TODO: not doing anything with this atm
        ),
    MediumLevelILOperation.MLIL_SUB:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_SBB:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size)),
            get_important=lambda mlil: [mlil.carry]
        ),
    MediumLevelILOperation.MLIL_AND:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_OR:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_XOR:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_LSL:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size)),
            get_important=lambda mlil: [lookupSrcs(mlil.right, mlil.size)]
        ),
    MediumLevelILOperation.MLIL_LSR:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size)),
            get_important=lambda mlil: [mlil.right] # TODO: not doing anything with this atm
        ),
    MediumLevelILOperation.MLIL_ASR:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size)),
            get_important=lambda mlil: [mlil.right]
        ),
    MediumLevelILOperation.MLIL_ROL:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size)),
            get_important=lambda mlil: [mlil.right]
        ),
    MediumLevelILOperation.MLIL_RLC:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size)),
            get_important=lambda mlil: [mlil.right,mlil.carry]
        ),
    MediumLevelILOperation.MLIL_ROR:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size)),
            get_important=lambda mlil: [mlil.right]
        ),
    MediumLevelILOperation.MLIL_RRC:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size)),
            get_important=lambda mlil: [mlil.right,mlil.carry]
        ),
    MediumLevelILOperation.MLIL_MUL:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_MULU_DP:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_MULS_DP:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_DIVU:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_DIVU_DP:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_DIVS:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_DIVS_DP:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size)) 
        ),
    MediumLevelILOperation.MLIL_MODU:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_MODU_DP:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_MODS:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_MODS_DP:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_NEG:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size))
        ),
    MediumLevelILOperation.MLIL_NOT:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size))
        ),
    MediumLevelILOperation.MLIL_FADD:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_FSUB:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size)),
            get_dests=lambda mlil: [VarKey(mlil.left, mlil.size)]
        ),
    MediumLevelILOperation.MLIL_FMUL:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_FDIV:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_FSQRT:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),
    MediumLevelILOperation.MLIL_FNEG:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size))
        ),
    MediumLevelILOperation.MLIL_FABS:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size))
        ),
    MediumLevelILOperation.MLIL_FLOAT_TO_INT:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size))
        ),
    MediumLevelILOperation.MLIL_INT_TO_FLOAT:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size))
        ),
    MediumLevelILOperation.MLIL_FLOAT_CONV:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size))
        ),
    MediumLevelILOperation.MLIL_ROUND_TO_INT:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size))
        ),
    MediumLevelILOperation.MLIL_FLOOR:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.src, mlil.size))
        ),
    MediumLevelILOperation.MLIL_CEIL:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.src, mlil.size))
        ),
    MediumLevelILOperation.MLIL_FTRUNC:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.src, mlil.size))
        ),
    MediumLevelILOperation.MLIL_SX:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size))
        ),
    MediumLevelILOperation.MLIL_ZX:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size))
        ),
    MediumLevelILOperation.MLIL_ADD_OVERFLOW:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.left, mlil.size), lookupSrcs(mlil.right, mlil.size))
        ),  # TODO: this might be incorrect, could have undocumented overflow property, verify in binaja
    MediumLevelILOperation.MLIL_BOOL_TO_INT:
        MLILOpInfo(
            'i',
            lambda mlil: Inherited(lookupSrcs(mlil.src, mlil.size))
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
