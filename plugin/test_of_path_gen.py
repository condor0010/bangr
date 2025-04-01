#!/usr/bin/env python3
import sys
import binaryninja

if len(sys.argv) < 2:
    sys.exit(f"Usage: {sys.argv[0]} <binary>")

path_table = {}

def walk_cfg(block, path, visited):
    if block in visited:
        return
    visited.add(block)
    
    for edge in block.outgoing_edges:
        if edge.type.name in ("TrueBranch", "FalseBranch"):
            new_path = path + [(edge.source.end, edge.type.name[:-6])]
            walk_cfg(edge.target, new_path, visited)
    
    if not block.outgoing_edges or all(edge.target in visited for edge in block.outgoing_edges):
        if path:
            path_table.setdefault(block.function, []).append(path)

with binaryninja.load(sys.argv[1]) as bv:
    for func in bv.functions:
        path_table[func] = []
        for block in func.basic_blocks:
            walk_cfg(block, [], set())

        for path in path_table[func]:
            path_int = sum((1 if decision == "True" else 0) << i for i, (_, decision) in enumerate(path[::-1]))
            print(f"[MILO]: {func.start:#08x} | {path_int} | {path_int:#08b}")
            print("\n".join(f"  {addr:#08x} {decision}" for addr, decision in path), "\n")

