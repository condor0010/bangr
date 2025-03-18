# TODO
Things to do, in no specific order.

### Z3 integration
- [ ] We can manipulate the mlil_op dictionary in mlil_op_map.py to include
build the z3 constraint as we parse an instruction. Each get_srcs func
would be modified to add another constraint based on which operation
the get_srcs func belongs to, ultimately being complete with the
VarKey(s) that are found at the end.

### Parsing/Accounting for all instructions
- [ ] Create generic way to account for MLIL_INTRINSIC_SSA instructions (these
are instructions that are arch specific, see sample libc and `intrinsic_addrs.py`
for examples)
- [ ] Download an ipsw off of https://ipsw.me/ and extract/test on extracted
daemons.
