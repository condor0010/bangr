from binaryninja.mediumlevelil import SSAVariable

class Taint():
    def __init__(self, taint):
        self.taint = taint

    # reminder that the lower the number the greater the taint
    def decrement(self):
        if self.taint is not None:
            self.taint += 1

    def __gt__(self, other):
        if self.taint == other.taint:
            return False
        if self.taint is None:
            return False
        elif other.taint is None:
            return True
        return self.taint < other.taint

    def __lt__(self, other):
        if self.taint == other.taint:
            return False
        elif self.taint is None:
            return True
        elif other.taint is None:
            return False
        return self.taint > other.taint

    def __ge__(self, other):
        if self.taint == other.taint:
            return True
        if self.taint is None:
            return False
        elif other.taint is None:
            return True
        return self.taint < other.taint

    def __le__(self, other):
        if self.taint == other.taint:
            return True
        elif self.taint is None:
            return True
        elif other.taint is None:
            return False
        return self.taint > other.taint

    def __eq__(self, other):
        return self.taint == other.taint

    def __ne__(self, other):
        return self.taint != other.taint

    def __repr__(self):
        return str(self.taint)

# TODO: add cache functionality so that evaluated taint trees
#       can be saved
class Table():
    def __init__(self, is_mem_table=False):
        self.table = {}
        self.is_mem_table = is_mem_table
        if not self.is_mem_table:
            self.mem_tables = {}
            # TODO: Must change when we want to give initially tainted memory
            self.mem_tables[0] = Table(is_mem_table=True)

    def get_taint(self, vkey):
        # check if entry for var exists
        # if exists, get entry and call get_taint on it
        # if not exists, return -1 or None for no taint at all
        print(f'Evaling for {vkey}')
        print(vkey.var in self.table)
        print(self.table)
        if vkey.is_mem and not self.is_mem_table:
            return self._get_mem_taint(vkey)
        elif vkey.var in self.table:
            return self.table[vkey.var].get_taint(vkey)
        else:
            return Taint(None)

    def _get_mem_taint(self, vkey):
        if vkey.mem_version in self.mem_tables:
            mem_table = self.mem_tables[vkey.mem_version]
            return mem_table.get_taint(vkey)
        return Taint(None)

    def set_taint(self, vkey, taint):
        # check if entry for var exists
        # if exists, get entry and call set_taint on it
        # if not exists, create new entry and save it to the table
        print("BEFORE")
        print(vkey)
        print(f'vkey.is_mem={vkey.is_mem}')
        if vkey.is_mem and not self.is_mem_table:
            print("AFTER")
            self._set_mem_taint(vkey, taint)
        elif vkey.var in self.table:
            self.table[vkey.var].set_taint(vkey, taint)
        else:
            print(f"SETTING TAINT FOR {vkey.var}")
            print(f'taint: {taint}')
            self.table[vkey.var] = self.Entry(vkey.size, vkey.offset, vkey.offset_sign, vkey.is_deref, taint, self)
            #print(self.table)

    def _set_mem_taint(self, vkey, taint):
        if vkey.mem_version in self.mem_tables:
            mem_table = self.mem_tables[vkey.mem_version]
            mem_table.set_taint(vkey, taint)
        else:
            mem_table = Table(is_mem_table=True)
            mem_table.set_taint(vkey, taint)
            self.mem_tables[vkey.mem_version] = mem_table

    def copy_var_taint(self, dest, src):
        if src in self.table:
            self.table[dest] = self.table[src]

    def copy_mem_taint(self, dest, src):
        # Mem table index will now point to the same instance
        self.mem_tables[dest] = self.mem_tables[src]

    def __repr__(self):
        string = "Table (\n"
        for k,v in self.table.items():
            string += f"\t{k}\n"
            string += f"\t\t{repr(v)}"
        string += ")\n"
        if self.is_mem_table:
            return string
        for k,v in self.mem_tables.items():
            string += f'Mem#{k} {repr(v)}'
        return string

    class Entry():
        def __init__(self, size, offset, sign, is_deref, taint, taint_table):
            self.taint_table = taint_table
            if is_deref:
                self.ranges = []
                self.deref_ranges = [[size, offset, sign, taint]]
            else:
                self.deref_ranges = []
                self.ranges = [[size, offset, sign, taint]]

        # TODO: doesnt work for all use cases, what if taint objects are modified in overlaps?
        def get_taint(self, vkey):
            # TODO: account for overlap with and without exact match, could affect taint
            # TODO: Account for if is deref
            for r in self.ranges:
                if r[0] == vkey.size and r[1] == vkey.offset and r[2] == vkey.offset_sign:
                    #if not int must be tree
                    if isinstance(r[3], Taint):
                        return r[3]
                    else:
                        print(f'Evaling taint for {r[3]}')
                        return r[3].eval(self.taint_table)
            return Taint(None)

        def set_taint(self, vkey, taint):
            # check if it exists, set if it does, or create new and set if it doesnt
            # TODO: account for if is deref
            for r in self.ranges:
                if r[0] == vkey.size and r[1] == vkey.offset and r[2] == vkey.offset_sign:
                    r[3] = taint
                    return True
            self.ranges.append([self.size, self.offset, self.sign, taint])
            return False

        # TODO
        def _check_overlap(self):
            return Taint(None)

        def __repr__(self):
            string = ''
            string += "Normal ranges:\n"
            for r in self.ranges:
                if isinstance(r[3], Taint):
                    string += f"\t\t\tTaint: {repr(r[3])}\n"
                else:
                    string += f"\t\t\tTaint: {repr(r[3])} = {repr(r[3].eval(self.taint_table))}\n"
            string += "\t\tDeref ranges:\n"
            for r in self.deref_ranges:
                if isinstance(r[3], Taint):
                    string += f"\t\t\tTaint: {repr(r[3])}\n"
                else:
                    string += f"\t\t\tTaint: {repr(r[3].eval(self.taint_table))}\n"
            string += '\n'
            return string