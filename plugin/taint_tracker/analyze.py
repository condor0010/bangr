import sys
import binaryninja
from collections import deque
import parser
from global_vars import *
from tree import *
from table import *

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
        #print(self.var)
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

# TODO: We have to locate all phi's in the function and their associated
# potential values. The latest seen value will be the value that is assigned
# in the phi.
def get_phis():
    return None

def analyze_block(block, state_taint_table): # return map
    for inst in block:
        if isinstance(inst, binaryninja.mediumlevelil.MediumLevelILVarPhi):
            # TODO: get latest phi from potential sources
            continue
        # TODO: Check if dest exists in symbol table, else save to state specific symbol table
        src_tree = parser.lookupSrcs(inst,inst.size)
        dests = parser.lookupDest(inst)
        # TODO: dest could be list, which means multiple dests or phi
        print(dests)
        #print(f'\tsrcs:')
        if isinstance(src_tree, str):
            if src_tree in parser.unknown_src_ops:
                parser.unknown_src_ops[src_tree].add(inst.address)
            else:
                parser.unknown_src_ops[src_tree] = {inst.address}
            #print(f'\t\taddress: {hex(self.def_inst.address)}\tmlil_op: {src_tree:32s}')
        # initialize the taint table with these src_trees
        elif isinstance(src_tree, list):
            # TODO: this signifies a phi, need to account for this
            #print(src_tree)
            continue
        else:
            for dest in dests:
                state_taint_table.set_taint(dest, src_tree)
            #print(f'\t\taddress: {hex(self.def_inst.address)}\tvariable: {repr(src_tree)}')


def walk_graph(first_block, path, state_taint_table):
    print("Walking graph")
    seen_blocks = {first_block}
    next_blocks = deque()
    next_blocks.append(first_block)
    print(f'length: {len(next_blocks)}')
    while len(next_blocks) != 0:
        next_block = next_blocks.popleft()
        print(next_block)
        analyze_block(next_block, state_taint_table)
        if len(next_block.outgoing_edges) == 2:
            # we're assuming true and false are the only possible options when there are 2 outgoing edges
            assert next_block.outgoing_edges[0].type == binaryninja.BranchType.FalseBranch or next_block.outgoing_edges[0].type == binaryninja.BranchType.TrueBranch
            assert next_block.outgoing_edges[1].type == binaryninja.BranchType.FalseBranch or next_block.outgoing_edges[0].type == binaryninja.BranchType.TrueBranch
            true_branch = None
            false_branch = None
            if next_block.outgoing_edges[0].type == binaryninja.BranchType.FalseBranch:
                false_branch = next_block.outgoing_edges[0].target
                true_branch = next_block.outgoing_edges[1].target
            else:
                true_branch = next_block.outgoing_edges[0].target
                false_branch = next_block.outgoing_edges[1].target
            # TODO: possible bug, if all bits provided have actually been expended 
            #       python will just keep provideing 0's, create `Path` object to
            #       store bits and path length
            next_branch = path & 1
            path = path >> 1
            if next_branch == 0:
                next_blocks.append(false_branch)
            else:
                next_blocks.append(true_branch)
        elif len(next_block.outgoing_edges) == 1:
            # As far as i know blocks can only be either true-false or a single unconditional
            assert len(next_block.outgoing_edges) == 1
            assert next_block.outgoing_edges[0].type == next_block.outgoing_edges[0].type == binaryninja.BranchType.UnconditionalBranch
            next_blocks.append(next_block.outgoing_edges[0].target)
        elif len(next_block.outgoing_edges) == 0:
            return True
        else:
            # unaccounted for, inspect this
            print(next_block.outgoing_edges)
            assert False

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

def gen_symbol_table(mlil_ssa_func):
    ssa_vars = mlil_ssa_func.vars
    for var in ssa_vars:
        if var.def_site:
            VarInfo(var)
        else: # are naturally version 0 ssa vars
            if is_tainted_arg(var):
                print(parser.VarKey(var, var.type.width))
                sym_tab.set_taint(parser.VarKey(var, var.type.width), Taint(0))
            else:
                sym_tab.set_taint(parser.VarKey(var, var.type.width), Taint(None))
    # base symbol table is populated at this point
    # TODO louie: sym_tab as the function specific symbol table instead of being global

# generate the base symbol table and then walk it based on a path
def analyze_function(mlil_ssa_func, path):
    # TODO: implement get_phis
    get_phis()
    bbs = mlil_ssa_func.basic_blocks
    # TODO: Check if the stated path has already been analyzed
    state_taint_table = table.Table()
    walk_graph(bbs[0], path, state_taint_table)
    print(state_taint_table)

def is_tainted_arg(var):
    # TODO louie: actual var names would be given by GUI
    args = ['arg1', 'arg2', 'arg3', 'arg4']
    if var.name in args:
        return True

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 {sys.argv[0]} [path to binary]")
        exit()

    with binaryninja.load(sys.argv[1]) as bv:
        parser.ADDR_SIZE = bv.address_size
        for function in bv.functions:
            if function.name != "main":
                continue
            mlil_func = function.mlil_if_available
            if mlil_func is None:
                unanalyzed_funcs.append(function.name)
            else:
                analyze_function(mlil_func.ssa_form, int('1010',2))
                print(sym_tab)
                sym_tab = table.Table()
        print_unknown_ops()
