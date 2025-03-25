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
    def __init__(self, var, size, offset=0, offset_sign='+'):
        self.var = var
        # could be SSAVariable, MediumLevelILConst, or VarKey
        #assert isinstance(var, SSAVariable)
        print(size)
        self.size = size
        self.offset = offset
        self.offset_sign = offset_sign
        self.var_only = True
        if self.offset is not None:
            print(self.size)
            assert self.size is not None
            self.var_only = False
        else:
            assert self.size is None

    def __repr__(self):
        return f'VarKey(v={self.var}, s={self.size}, o={self.offset}, os={self.offset_sign})'

    # TODO
    # table will be at least 2 layers: first is the var it affects,
    # next is the part of the var it affects
    def eval(self):
        return None

# represent an operation that directly transfers taint
class OneToOne:
    def __init__(self, src):
        self.src = src

    def __repr__(self):
        return f'OneToOne({repr(self.src)})'
    
    def eval(self):
        return self.src.eval()

# represents an operation that will select the highest taint from one or
# more sources, then decrement it.
class Inherited:
    def __init__(self, *srcs):
        assert len(srcs) > 0
        self.srcs = srcs

    def __repr__(self):
        internal = ','.join(list(map(lambda s: repr(s), self.srcs)))
        return f'Inherited({internal})'

    def eval(self):
        # reminder that the lower the number the higher the taint
        max_taint = self.srcs[0].eval()
        for i in range(1, len(self.srcs)):
            taint = s.eval()
            if taint < max_taint:
                max_taint = taint
        return max_taint + 1

def lookupSrcs(mlil, size):
    if isinstance(mlil, SSAVariable):
        return VarKey(mlil, size)
    if isinstance(mlil, MediumLevelILConst):
        return VarKey(mlil, size)
    dict_value = op_map.get(mlil.operation, mlil.operation.name)
    # debugging
    if isinstance(dict_value, str) or dict_value is None:
        return mlil.operation.name
    print(mlil.operation.name)
    # continue recursive lookup
    return dict_value.get_srcs(mlil)

# must return VarKey
# TODO: could be more than just one op happening in load, saw bitshift in dest once along with add
def srcLoadLookup(mlil, size):
    if isinstance(mlil, MediumLevelILVarSsa):
        return VarKey(mlil.src, size, offset=0)
    if isinstance(mlil, MediumLevelILConstData):
        const_data = mlil.const_data
        return VarKey(const_data.value, size, offset=const_data.offset)
    if isinstance(mlil, MediumLevelILConst) or isinstance(mlil, MediumLevelILConstPtr) or isinstance(mlil, MediumLevelILImport):
        return VarKey(mlil, size, offset=0)
    if isinstance(mlil, MediumLevelILAdd):
        #op_info = op_map.get(mlil)
        #srcs = op_info.get_srcs(mlil)
        return VarKey(mlil.left, size, offset=mlil.right)
    if isinstance(next_mlil, MediumLevelILSub):
        return VarKey(next_mlil.left, size, offset=next_mlil.right, offset_sign='-')
    print(f'Unnaccounted for type at {hex(mlil.address)}: {mlil.operation.name}')
    assert False


def lookupDest(mlil):
    if isinstance(mlil, MediumLevelILStoreSsa):
        # TODO: this is gross
        next_mlil = mlil.dest
        if isinstance(next_mlil, MediumLevelILAdd):
            return [VarKey(next_mlil.left, mlil.size, offset=next_mlil.right)]
        if isinstance(next_mlil, MediumLevelILSub):
            return [VarKey(next_mlil.left, mlil.size, offset=next_mlil.right, offset_sign='-')]
        if isinstance(mlil, MediumLevelILConstData):
            const_data = mlil.const_data
            return [VarKey(const_data.value, const_data.size, offset=const_data.offset)]
        if isinstance(next_mlil, MediumLevelILConst) or isinstance(next_mlil, MediumLevelILConstPtr) or isinstance(next_mlil, MediumLevelILImport):
            return [VarKey(next_mlil, next_mlil.size, offset=0)]
        if isinstance(next_mlil, MediumLevelILVarSsa):
            return [VarKey(next_mlil.src, next_mlil.size, offset=0)]
        print(f'Unaccounted for type in StoreSsa Dest at {hex(mlil.address)}: {next_mlil.operation.name}')
        assert False
    dict_value = op_map.get(mlil.operation, mlil.operation.name)
    if isinstance(dict_value, str) or dict_value is None:
        return [mlil.operation.name]
    print(mlil.operation.name)
    return dict_value.get_dests(mlil)

# TODO: could be more than just one op happening in load, saw bitshift in dest once along with add
def destStoreLookup(mlil, size):
    if isinstance(next_mlil, MediumLevelILAdd):
        return [VarKey(next_mlil.left, mlil.size, offset=next_mlil.right)]
    if isinstance(next_mlil, MediumLevelILSub):
        return [VarKey(next_mlil.left, mlil.size,offset=next_mlil.right, offset_sign='-')]
    if isinstance(mlil, MediumLevelILConstData):
        const_data = mlil.const_data
        return [VarKey(const_data.value, const_data.size, offset=const_data.offset)]
    if isinstance(next_mlil, MediumLevelILConst) or isinstance(next_mlil, MediumLevelILConstPtr) or isinstance(next_mlil, MediumLevelILImport):
        return [VarKey(next_mlil, next_mlil.size, offset=0)]
    if isinstance(next_mlil, MediumLevelILVarSsa):
        return [VarKey(next_mlil.src, next_mlil.size, offset=0)]
    print(f'Unaccounted for type in StoreSsa Dest at {hex(mlil.address)}: {next_mlil.operation.name}')
    assert False

# TODO: All of the tuple elements below are special cases I don't know how to account for yet.
# We need to figure out how to turn them into a SSA vars that we can look up in our taint map.
# TODO: Constants currently return their associated constant. Need to figure out how to return
# constant info properly, or at least handle it.
# TODO: create get_dests for every atomic operation

# lookup: op_map[mlil.operation].get_srcs(mlil.attr)
op_map = {
    MediumLevelILOperation.MLIL_SET_VAR_SSA:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size)),
            get_dests=lambda mlil: [VarKey(mlil.dest, mlil.size)]
        ),
# TODO: Account for special case
    MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size)),
            get_dests=lambda mlil: [VarKey(mlil.dest, mlil.size)]
        ),
# Prob when something like `var_c#0:0.d # mem#<x> -> mem#<x+1>` is on LHS
    MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size)),
            get_dests=lambda mlil: [VarKey(mlil.src, mlil.size, offset=mlil.offset)]
        ),
# the below likely looks like `__return_addr#0:0.d` on LHS
    MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size)),
            # could there be situation where dest is not an ssa var?
            get_dests=lambda mlil: [VarKey(mlil.dest, mlil.size, offset=mlil.offset)]
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
            lambda mlil: srcLoadLookup(mlil.src, mlil.size)
        ),
    MediumLevelILOperation.MLIL_LOAD_STRUCT_SSA:
        MLILOpInfo(
            'a',
            lambda mlil: VarKey(mlil.src, mlil.size, offset=mlil.offset)
        ),
# dest could just be const or ssa_var, but could also be an MLIL_ADD
    MediumLevelILOperation.MLIL_STORE_SSA:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size)),
            get_dests=lambda mlil: srcLoadLookup(mlil.dest, mlil.size)
        ),
    MediumLevelILOperation.MLIL_STORE_STRUCT_SSA:
        MLILOpInfo(
            'o',
            lambda mlil: OneToOne(lookupSrcs(mlil.src, mlil.size)),
            get_dests=lambda mlil: [VarKey(mlil.dest, mlil.size, offset=mlil.offset)]
            #get_dests=lambda mlil: srcLoadLookup(mlil.mlil, mlil.size)
        ),
    MediumLevelILOperation.MLIL_VAR_SSA:
        MLILOpInfo(
            'a',
            lambda mlil: VarKey(mlil.src, mlil.size),
            get_dests=lambda mlil: [VarKey(mlil.src, mlil.size)]
        ),
    # TODO: This is a special case, whatever this is set equal to will have the same
    #       taint entry as this
#    MediumLevelILOperation.MLIL_VAR_ALIASED:
#        MLILOpInfo(
#            'a',  # technically also oto
#            lambda mlil: VarKey(mlil.src, size=mlil.size)
#        ),
# TODO: Verify, prob looks something like `var_c#0:0.d @ mem<x> -> mem<x+1>`
    MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD:
        MLILOpInfo(
            'a',
            lambda mlil: VarKey(mlil.src, mlil.size, offset=mlil.offset)
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
# find example of VAR_SPLIT being used, likely just an Inherited use case
#    MediumLevelILOperation.MLIL_VAR_SPLIT_SSA:
#        MLILOpInfo(
#            'a',
#            lambda mlil: Inherited(VarKey(mlil.high, mlil.size), (VarKey(mlil.low, mlil.size)))
#        ),
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
    MediumLevelILOperation.MLIL_ADDRESS_OF:
        MLILOpInfo(
            'a',
            #TODO src could be of type `binaryninja.variable.Variable`
            lambda mlil: VarKey(mlil.src, mlil.size) # size technically comes to 0
        ),
# TODO: This will be special case where addr of field is gotten, so field could be
# referenced via means of this new pointer that's generated
    MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD:
        MLILOpInfo(
            'a',
            lambda mlil: VarKey(mlil.address, mlil.size, mlil.offset)
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
# TODO: Special case, how do we treat it?
#    MediumLevelILOperation.MLIL_EXTERN_PTR:
#        MLILOpInfo(
#            'a',
#            lambda mlil: [(mlil.constant,mlil.symbol)]
#        ),
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
    MediumLevelILOperation.MLIL_LOW_PART:
        MLILOpInfo(
           'a',
           lambda mlil: VarKey(mlil.src, mlil.size, offset=0)
        ),
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
