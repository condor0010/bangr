#include <vector>
#include <stdio.h>
#include <string>
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
    int addr_arg = std::stoi(argv[2], nullptr, 16);

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
    Ref<MediumLevelILFunction> il = function->GetMediumLevelIL()->GetSSAForm();
    std::set<SSAVariable> vars = function->GetMediumLevelILSSAVariables();

    printf("Finding SSA Variables...\n");
    for (SSAVariable var : vars) {
        printf("%s#%u\n", function->GetVariableName(var.var).c_str(), var.version);
    }
    puts("");
    
    printf("Analyzing function...\n");
    for (auto& block : il->GetBasicBlocks()) {
        printf("Basic block: %p\n", (void*)block->GetStart());
        
        for (size_t instrIndex = block->GetStart(); instrIndex < block->GetEnd(); instrIndex++) {
            MediumLevelILInstruction instr = (*il)[instrIndex];
            vector<InstructionTextToken> tokens;

            il->GetInstructionText(function, function->GetArchitecture(), instrIndex, tokens);
            printf("    Instruction @ 0x%" PRIx64 ": ", instr.address);

            for (const auto& token : tokens) {
                printf("%s ", token.text.c_str());
            }
            printf("\n");

            // printf("    SSA: ");
            // for (const auto& token : tokens) {
            //     printf("%s ", token.text.c_str());
            // }
            // printf("\n");
        }
    }
    return 0;
}

