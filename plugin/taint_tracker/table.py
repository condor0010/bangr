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

class Table():
    def __init__(self):
        self.table = {}

    def get_taint(self, vkey):
        # check if entry for var exists
        # if exists, get entry and call get_taint on it
        # if not exists, return -1 or None for no taint at all
        if vkey.var in self.table:
            return self.table[vkey.var].get_taint(vkey)
        else:
            return Taint(None)

    def set_taint(self, vkey, taint):
        # check if entry for var exists
        # if exists, get entry and call set_taint on it
        # if not exists, create new entry and save it to the table
        if vkey.var in self.table:
            self.table[vkey.var].set_taint(vkey, taint)
        else:
            print(f"SETTING TAINT FOR {vkey.var}")
            self.table[vkey.var] = self.Entry(vkey.size, vkey.offset, vkey.offset_sign, taint)
            print(self.table)
    
    def __repr__(self):
        string = "Table (\n"
        for k,v in self.table.items():
            string += f"\t{k}\n"
            string += f"\t\t{repr(v)}"
        string += ")\n"
        return string

    class Entry():
        def __init__(self, size, offset, sign, taint):
            self.ranges = [[size, offset, sign, taint]]

        # TODO: doesnt work for all use cases, what if taint objects are modified in overlaps?
        def get_taint(self, vkey):
            # TODO: account for overlap with and without exact match, could affect taint
            for r in self.ranges:
                if r[0] == vkey.size and r[1] == vkey.offset and r[2] == vkey.offset_sign:
                    #if not int must be tree
                    if isinstance(r[3], Taint):
                        return r[3]
                    else:
                        return r[3].eval()
            return Taint(None)

        def set_taint(self, vkey, taint):
            # check if it exists, set if it does, or create new and set if it doesnt
            for r in self.ranges:
                if r[0] == vkey.size and r[1] == vkey.offset and r[2] == vkey.offset_sign:
                    r[3] = taint
                    return True
            self.ranges.append([self.size, self.offset, self.sign, taint])
            return False

        def check_overlap(self):
            return Taint(None)

        def __repr__(self):
            string = ''
            for r in self.ranges:
                if isinstance(r[3], Taint):
                    string += f"Taint: {repr(r[3])}\n"
                else:
                    string += f"Taint: {repr(r[3].eval())}\n"
            string += '\n'
            return string
