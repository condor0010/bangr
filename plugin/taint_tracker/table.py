from binaryninja.mediumlevelil import SSAVariable

class Taint():
    def __init__(self, taint):
        self.taint = taint

    # reminder that the lower the number the greater the taint
    def decrement(self):
        if self.taint is not None:
            return Taint(self.taint+1)
        return Taint(None)

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
        print(f'Getting Taint for {vkey}')
        if vkey.is_mem and not self.is_mem_table:
            print('is mem table')
            taint = self._get_mem_taint(vkey)
            print(f'taint: {taint}')
            return taint
        elif vkey.var in self.table:
            print(self.table[vkey.var])
            taint = self.table[vkey.var].get_taint(vkey)
            print(f'taint: {taint}')
            return taint
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
            print(f'Setting existing: {vkey.var}')
            self.table[vkey.var].set_taint(vkey, taint)
        else:
            print(f"SETTING TAINT FOR {vkey.var}")
            print(f'taint: {taint}')
            assert taint is not None
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

    def copy_var_taint_for_phi(self, dest, src):
        # TODO: add phi iteration index to Entry
        if src in self.table:
            # must eval all to prevent unevaled references from previous loop from becoming outdated
            print(f'Phi hit for {dest}')
            #print(f'{}')
            print(f'Evaling all for {src}')
            self.table[src].eval_all()
            self.table[dest] = self.table[src]
            print(f'AFTER EVAL: {self.table[dest]}')

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
        def __init__(self, size, offset, sign, is_deref, taint, taint_table, is_phi=False):
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
            if vkey.is_deref:
                for r in self.deref_ranges:
                    if r[0] == vkey.size and r[1] == vkey.offset and r[2] == vkey.offset_sign:
                        #if not int must be tree
                        if isinstance(r[3], Taint):
                            return r[3]
                        else:
                            print(f'Evaling taint for {r[3]}')
                            r[3] = r[3].eval(self.taint_table)
                            return r[3]
            else:
                for r in self.ranges:
                    if r[0] == vkey.size and r[1] == vkey.offset and r[2] == vkey.offset_sign:
                        #if not int must be tree
                        if isinstance(r[3], Taint):
                            return r[3]
                        else:
                            print(f'Evaling taint for {r[3]}')
                            print(type(r[3]))
                            r[3] = r[3].eval(self.taint_table)
                            return r[3]
            return Taint(None)

        def set_taint(self, vkey, taint):
            # check if it exists, set if it does, or create new and set if it doesnt
            if vkey.is_deref:
                for r in self.deref_ranges:
                    if r[0] == vkey.size and r[1] == vkey.offset and r[2] == vkey.offset_sign:
                        r[3] = taint
                        return True
                self.deref_ranges.append([vkey.size, vkey.offset, vkey.sign, taint])
            else:
                for r in self.ranges:
                    if r[0] == vkey.size and r[1] == vkey.offset and r[2] == vkey.offset_sign:
                        r[3] = taint
                        return True
                self.ranges.append([vkey.size, vkey.offset, vkey.sign, taint])
            return False

        # TODO
        def _check_overlap(self):
            return Taint(None)

        def eval_all(self):
            # TODO: account for overlap with and without exact match, could affect taint
            # TODO: Account for if is deref
            for r in self.deref_ranges:
                #if not int must be tree
                if isinstance(r[3], Taint):
                    continue
                else:
                    print(f'Evaling taint for {r[3]}')
                    print(f'evaluated taint: {r[3].eval(self.taint_table)}')
                    r[3] = r[3].eval(self.taint_table)
            for r in self.ranges:
                #if not int must be tree
                if isinstance(r[3], Taint):
                    continue
                else:
                    print(f'Evaling taint for {r[3]}')
                    r[3] = r[3].eval(self.taint_table)

        def __repr__(self):
            string = ''
            string += "Normal ranges:\n"
            for r in self.ranges:
                print(f'normal ranges: {type(r[3])}')
                if isinstance(r[3], Taint):
                    string += f"\t\t\tTaint: {repr(r[3])}\n"
                else:
                    string += f"\t\t\tTaint: {repr(r[3])}\n"#={repr(r[3].eval(self.taint_table))}\n"
            string += "\t\tDeref ranges:\n"
            for r in self.deref_ranges:
                print(f'deref ranges: {type(r[3])}')
                if isinstance(r[3], Taint):
                    string += f"\t\t\tTaint: {repr(r[3])}\n"
                else:
                    string += f"\t\t\tTaint:  {repr(r[3])}\n"#={repr(r[3].eval(self.taint_table))}\n"
            string += '\n'
            return string

    # Does phi entry only need to be gotten, not set?
    class PhiEntry():
        def __init__(self, reference_index, entry_array):
            self.ref_index = reference_index
            self.entry_array = entry_array

        def get_taint(self):
            return self.entry_array[self.ref_index].get_taint()

        def increment(self):
            self.ref_index += 1

        def add_taint(self, new_taint):
            entry_array.append(new_taint)