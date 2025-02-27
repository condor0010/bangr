import sys
import binaryninja
from collections import deque
from mlil_op_map import op_map

# 3 types of mlil instructions: one-to-one, inherited, atomic.
# `one-to-one means` means the operation will propagate the
# same taint as one of the parent variables no matter what.
# `inherited` means the operation will decrement the taint of
# the most tainted parent variable (may change to be more precise)
# `atomic` means that this operation actually just holds an variable,
# so we'll just look up the taint of this variable for use within the
# encompasing operation.

# when looking at ssa vars, we need their def site (.def_site), their
# use sites (.use_site), the blocks they belong to (.il_basic_block),
# overall op is inherited or oto, the ssa_var parent(s) that are
# inherited from, the children that they affect

class VarInfo():
    def __init__(self, ssa_var):
        self.operation = ssa_var.operation
        self.def_inst = ssa_var.def_site
        self.use_insts = ssa_var.use_sites
        self.taint_type = []
        self.taint_srcs = []
        self.taint_dests = []
        self._initialize_tsd()

    def _initialize_tsd(self):
        mlil_obj = op_map[self.def_inst.operation]
        self.taint_type = mlil_obj.taint_type
        self.taint_srcs = mlil_obj.get_srcs(self.def_inst.src)
        self.taint_dests = mlil_obj.get_dests(self.def_inst.dest)
        return op_map[self.def_site.operation]

def initialize_var_map(ssa_vars):
    for sv in ssa_vars:
        sv.def_site
        sv.use_sites

def analyze_block(block): # return map
    var_ops = []
    for inst in block:
        var_ops.append(inst)
        print(inst.operation)
        if inst.operation == 'MLIL_SET_VAR':
            continue
        elif inst.operation == 'MLIL_SET_VAR_ALIASED':
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

def walk_graph(first_block, ssa_vars):
    seen_blocks = {first_block}
    next_blocks = deque()
    next_blocks.append(first_block)
    while len(next_blocks) != 0:
        next_block = next_blocks.popleft()
        analyze_block(next_block)
        [(next_blocks.append(child),seen_blocks.add(child)) for child in [edge.target for edge in next_block.outgoing_edges] if child not in seen_blocks]

def analyze_function(mlil_ssa_func):
    bbs = mlil_ssa_func.basic_blocks
    ssa_vars = mlil_ssa_func.vars
    walk_graph(bbs[0], ssa_vars) # assumes index 0 is first block

if len(sys.argv) != 2:
    print(sys.argv)
    exit()

with binaryninja.open_view(sys.argv[1]) as bv:
    for function in bv.functions:
        print(function.name)
        analyze_function(function.mlil.ssa_form)
