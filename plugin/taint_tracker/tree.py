from binaryninja.mediumlevelil import SSAVariable
from global_vars import sym_tab
# TODO: Size MUST be specified in initialization
class VarKey():
    def __init__(self, var, size, offset=0, offset_sign='+', is_deref=False):
        self.var = var
        # could be SSAVariable, some sort of constant, or 
        #assert isinstance(var, SSAVariable)
        self.size = size
        self.offset = offset
        self.offset_sign = offset_sign
        self.var_only = True
        self.is_deref = is_deref
        if self.offset is not None:
            assert self.size is not None
            self.var_only = False
        else:
            assert self.size is None

    def __repr__(self):
        return f'VarKey(v={self.var}, s={self.size}, o={self.offset}, os={self.offset_sign}, id={self.is_deref})'

    # TODO
    # table will be at least 2 layers: first is the var it affects,
    # next is the part of the var it affects
    # this is where taint is looked up 
    def eval(self):
        # TODO: this will have to be the taint_map for the current
        # state
        return sym_tab.get_taint(self)

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
        max_taint = self.srcs[0].eval()
        for i in range(1, len(self.srcs)):
            taint = self.srcs[i].eval()
            if taint > max_taint:
                max_taint = taint
        return max_taint.decrement()
