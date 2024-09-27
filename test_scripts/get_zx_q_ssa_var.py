import binaryninja

bv = binaryninja.load('./test')
#bv.update_analysis_and_wait() #is this even really useful?

### Some basic block properties
#outgoing_edges
#incoming_edges
f = bv.get_functions_by_name("main")[0]
cur_mlil = f.medium_level_il
        
first_block = cur_mlil.basic_blocks[0]
inst_w_mem1 = first_block[4]
print(f'Instruction: {inst_w_mem1.ssa_form}')
print(f'Should be SSA var: {inst_w_mem1.ssa_form.dest}')
print(f'Src is MediumLevelILZx: {inst_w_mem1.ssa_form.src}')
print(f'Src of Src is MediumLevelILVarAliased: {inst_w_mem1.ssa_form.src.src}')
