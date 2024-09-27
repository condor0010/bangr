import binaryninja

def in_block(block, inst):
    if inst.address >= block[0].address and inst.address <= block[-1].address:
        return True
    return False

bv = binaryninja.load('./test')
#bv.update_analysis_and_wait() #is this even really useful?

### Some basic block properties
f = bv.get_functions_by_name("func")[0]
f_mlil = f.medium_level_il

block_to_insts = {}
for bb in f_mlil.basic_blocks:
    block_to_insts[bb] = []
print(block_to_insts)
ssa_vars = f_mlil.ssa_vars

# when actually implemented, we can map every ssa var that has taint
# to the blocks they are used in
for ssa_var in ssa_vars:
    #print(f_mlil.get_ssa_var_definition(ssa_var)) #we assume we know where its defined?
    for bb in f_mlil.basic_blocks:
        uses = f_mlil.get_ssa_var_uses(ssa_var)
        for use in uses:
            if in_block(bb, use):
                block_to_insts[bb].append(use)

print(block_to_insts)
