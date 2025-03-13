### Z3 integration
We can manipulate the mlil_op dictionary in mlil_op_map.py to include
build the z3 constraint as we parse an instruction. Each get_srcs func
would be modified to add another constraint based on which operation
the get_srcs func belongs to, ultimately being complete with the
VarKey(s) that are found at the end.
