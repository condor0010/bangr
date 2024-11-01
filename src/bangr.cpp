#include <vector>
#include <string>
#include <cinttypes>
#include <map>
#include <set>
#include <sstream>
#include <iostream>

#include "blockAnalyze.h"
#include "binaryninjaapi.h"
#include "binaryninjacore.h"
#include "mediumlevelilinstruction.h"

using namespace std;
using namespace BinaryNinja;

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " <binary> <address>\n";
        return 1;
    }

    char* binary_arg = argv[1];
    int addr_arg = std::stoi(argv[2], nullptr, 16);

    SetBundledPluginDirectory(GetBundledPluginDirectory());
    InitPlugins();

    Ref<BinaryView> bv = BinaryNinja::Load(binary_arg);
    if (!bv) {
        std::cout << "Failed to load binary: " << binary_arg << "\n";
        return 1;
    }

    std::vector<Ref<Function>> funcs = bv->GetAnalysisFunctionsForAddress(addr_arg);
    if (funcs.empty()) {
        std::cout << "No functions found at address: 0x" << std::hex << addr_arg << "\n";
        return 1;
    }

    Ref<Function> function = funcs[0];
    Ref<MediumLevelILFunction> il = function->GetMediumLevelIL()->GetSSAForm();
    std::set<SSAVariable> vars = function->GetMediumLevelILSSAVariables();

    std::map<SSAVariable, VariableOperations> variableOps;

    std::cout << "Finding SSA Variables...\n";
    for (SSAVariable var : vars) {
        std::cout << function->GetVariableName(var.var) << "#" << var.version << "\n";
    }
    std::cout << "\n";

    std::cout << "Analyzing function...\n";

    blockAnalyze(il);

    std::cout << "\nSSA Variable Operations:\n";

    for (const auto& pair : variableOps) {
        const SSAVariable& var = pair.first;
        const VariableOperations& ops = pair.second;

        std::ostringstream varInfo;
        varInfo << "Variable " << function->GetVariableName(var.var) << "#" << var.version << ":\n";
        std::cout << varInfo.str();
        for (const auto& op : ops.operations) {
            std::cout << "\t" << op << "\n";
        }
    }

    return 0;
}

