#include <vector>
#include <stdio.h>
#include <cinttypes>

#include "binaryninjaapi.h"
#include "binaryninjacore.h"
#include "mediumlevelilinstruction.h"

using namespace std;
using namespace BinaryNinja;

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("%s <binary> <address>\n", argv[0]);
        return 1;
    }

    char* binary_arg = argv[1];
    int addr_arg = atoi(argv[2]);

    SetBundledPluginDirectory(GetBundledPluginDirectory());
    InitPlugins();

   
    Ref<BinaryView> bv = BinaryNinja::Load(binary_arg);
    if (!bv) {
        printf("Failed to load binary: %s\n", binary_arg);
        return 1;
    }

   
    std::vector<Ref<Function>> funcs = bv->GetAnalysisFunctionsForAddress(addr_arg);
    if (funcs.empty()) {
        printf("No functions found at address: 0x%x\n", addr_arg);
        return 1;
    }

    Ref<Function> function = funcs[0];
    Ref<MediumLevelILFunction> il = function->GetMediumLevelIL();
    
    printf("Analyzing function...\n");
    for (auto& block : il->GetBasicBlocks()) {
	// for each block in the desired fcn we will eventualy make workers to do the analisys and recombine later (that goes here)
        printf("Basic block: %p\n", block);
        for (size_t instrIndex = block->GetStart();instrIndex < block->GetEnd();instrIndex++) {
            MediumLevelILInstruction instr = (*il)[instrIndex];
            vector<InstructionTextToken> tokens;
            il->GetInstructionText(function, function->GetArchitecture(), instrIndex, tokens);
            printf("    %" PRIdPTR " @ 0x%" PRIx64 "\n", instrIndex, instr.address);
        }
    }

    return 0;
}

