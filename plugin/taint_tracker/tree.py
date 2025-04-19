from binaryninja.mediumlevelil import SSAVariable
from global_vars import sym_tab
# TODO: Size MUST be specified in initialization
class VarKey():
    # is_deref is if the the var, size, and offset are treated like a pointer
    # is_mem denotes the variable is stored in the memory space
    # mem_version is the memory version that a variable is being referenced from
    def __init__(self, var, size, offset=0, offset_sign='+', is_deref=False, is_mem=False, mem_version=None):
        self.var = var
        self.size = size
        self.offset = offset
        self.offset_sign = offset_sign
        self.var_only = True
        self.is_deref = is_deref
        self.is_mem = is_mem
        assert mem_version is not None if is_mem else True
        self.mem_version = mem_version
        if self.offset is not None:
            assert self.size is not None
            self.var_only = False
        else:
            assert self.size is None

    def __repr__(self):
        return f'VarKey(v={self.var}, s={self.size}, o={self.offset}, os={self.offset_sign}, id={self.is_deref}, im={self.is_mem}, mv={self.mem_version})'

    def eval(self, taint_table):
        return taint_table.get_taint(self)

# represent an operation that directly transfers taint
class OneToOne:
    def __init__(self, src):
        self.src = src

    def __repr__(self):
        return f'OneToOne({repr(self.src)})'

    def eval(self, taint_table):
        return self.src.eval(taint_table)

# represents an operation that will select the highest taint from one or
# more sources, then decrement it.
class Inherited:
    def __init__(self, *srcs):
        assert len(srcs) > 0
        self.srcs = srcs

    def __repr__(self):
        internal = ','.join(list(map(lambda s: repr(s), self.srcs)))
        return f'Inherited({internal})'

    def eval(self, taint_table):
        max_taint = self.srcs[0].eval(taint_table)
        for i in range(1, len(self.srcs)):
            taint = self.srcs[i].eval(taint_table)
            if taint > max_taint:
                max_taint = taint
        return max_taint.decrement()
