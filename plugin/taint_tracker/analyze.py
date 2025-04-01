import sys
import binaryninja
from collections import deque
import parser
from global_vars import *
from tree import *
from table import Taint

# 3 types of mlil instructions: one-to-one, inherited, atomic.
# `one-to-one means` means the operation will propagate the
# same taint as one of the parent variables no matter what.
# `inherited` means the operation will decrement the taint of
# the most tainted parent variable (may change to be more precise)
# `atomic` means that this operation actually just holds an variable,
# so we'll just look up the taint of this variable for use within the
# encompasing operation.

# for debugging:
unknown_dest_ops = {}
unanalyzed_funcs = []

# when looking at ssa vars, we need their def site (.def_site), their
# use sites (.use_site), the blocks they belong to (.il_basic_block),
# overall op is inherited or oto, the ssa_var parent(s) that are
# inherited from, the children that they affect
class VarInfo():
    def __init__(self, ssa_var):
        self.var = ssa_var
        self.def_inst = ssa_var.def_site
        # use site not necessarily on rhs, see below example where rax_86#198 is var in question:
        # [r13_4#31 + rax_86#198].d = rdx_54#109 @ mem#101 -> mem#102
        self.use_insts = ssa_var.use_sites
        self.taint_srcs = []
        self.taint_dests = []
        self._initialize_tsd()

    def _initialize_tsd(self):
        print(self.var)
        tree = parser.lookupSrcs(self.def_inst,self.def_inst.size)
        print(f'\tsrcs:')
        if isinstance(tree, str):
            if tree in parser.unknown_src_ops:
                parser.unknown_src_ops[tree].add(self.def_inst.address)
            else:
                parser.unknown_src_ops[tree] = {self.def_inst.address}
            print(f'\t\taddress: {hex(self.def_inst.address)}\tmlil_op: {tree:32s}')
        # initialize the symbol table with these trees
        elif isinstance(tree, list):
            print(tree)
        else:
            sym_tab.set_taint(parser.VarKey(self.var, self.def_inst.size), tree)
            print(f'\t\taddress: {hex(self.def_inst.address)}\tvariable: {repr(tree)}')
        #self.taint_dests = mlil_obj.get_dests(self.def_inst.dest)
        
def analyze_block(block): # return map
    var_ops = []
    for inst in block:
        var_ops.append(inst)
        #print(inst.operation)
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

# for debugging
def print_unknown_ops():
    # will print out ops that are unaccounted for
    print('Srcs:')
    for k, l in parser.unknown_src_ops.items():
        print(f'\tUnknown Operation: {k}')
        print(f'\t\tOccurrences:')
        for e in l:
            print(f'\t\t\t{hex(e)}')
    print('Dests:')
    for k, l in unknown_dest_ops.items():
        print(f'\tUnknown Operation: {k}')
        print(f'\t\tOccurrences:')
        for e in l:
            print(f'\t\t\t{hex(e)}')
    print('Unanalyzed Funcs:')
    for f in unanalyzed_funcs:
        print(f'\t{f}')


def analyze_function(mlil_ssa_func):
    bbs = mlil_ssa_func.basic_blocks
    ssa_vars = mlil_ssa_func.vars
    print(ssa_vars)
    #walk_graph(bbs[0], ssa_vars) # assumes index 0 is first block
    for var in ssa_vars:
        if var.def_site:
            VarInfo(var)
        else: # are naturally version 0 ssa vars
            if is_tainted_arg(var):
                print(parser.VarKey(var, var.type.width))
                sym_tab.set_taint(parser.VarKey(var, var.type.width), Taint(0))
            else:
                sym_tab.set_taint(parser.VarKey(var, var.type.width), Taint(None))

def is_tainted_arg(var):
    # TODO: actual var names would be given by GUI
    args = ['arg1', 'arg2', 'arg3', 'arg4']
    if var.name in args:
        return True

if len(sys.argv) != 2:
    print("Usage: python3 {sys.argv[0]} [path to binary]")
    exit()

with binaryninja.load(sys.argv[1]) as bv:
    parser.ADDR_SIZE = bv.address_size
    for function in bv.functions:
        mlil_func = function.mlil_if_available
        if mlil_func is None:
            unanalyzed_funcs.append(function.name)
        else:
            print(function.name)
            if function.name != "func":
                continue
            analyze_function(mlil_func.ssa_form)
            print(sym_tab)
            sym_tab = table.Table()
    print_unknown_ops()
