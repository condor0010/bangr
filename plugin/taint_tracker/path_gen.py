import binaryninja
from functools import lru_cache

class CFGPathExtractor:
    def __init__(self, function):
        self.function = function
        self._path_table = []

    def get_paths(self):
        if self._path_table:
            return self._path_table

        visited_global = set()
        for block in self.function.basic_blocks:
            self._walk_cfg(block, [], set(), visited_global)

        return self._path_table

    def _walk_cfg(self, block, path, visited_local, visited_global):
        if block in visited_local:
            return
        visited_local.add(block)

        for edge in block.outgoing_edges:
            if edge.type.name in ("TrueBranch", "FalseBranch"):
                new_path = path + [(edge.source.end, edge.type.name[:-6])]
                self._walk_cfg(edge.target, new_path, visited_local.copy(), visited_global)

        if not block.outgoing_edges or all(edge.target in visited_local for edge in block.outgoing_edges):
            if path and block not in visited_global:
                self._path_table.append(path)
                visited_global.add(block)

    @lru_cache(maxsize=None)
    def get_path_ints(self):
        return [
            sum((1 if decision == "True" else 0) << i for i, (_, decision) in enumerate(path[::-1]))
            for path in self.get_paths()
        ]


if __name__ == "__main__":
    import sys
    with binaryninja.load(sys.argv[1]) as bv:
        for func in bv.functions:
            extractor = CFGPathExtractor(func)
            paths = extractor.get_paths()
            path_ints = extractor.get_path_ints()

            for path, path_int in zip(paths, path_ints):
                print(f"[MILO]: {func.name} | {path_int} | {path_int:#08b}")
                print("\n".join(f"  {addr:#08x} {decision}" for addr, decision in path), "\n")

