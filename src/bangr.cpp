#include <vector>
#include <string>
#include <cinttypes>
#include <map>
#include <set>
#include <sstream>
#include <iostream>

#include "binaryninjaapi.h"
#include "binaryninjacore.h"
#include "mediumlevelilinstruction.h"

using namespace std;
using namespace BinaryNinja;

struct VariableOperations {
    std::vector<std::string> operations;
};

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
    for (auto& block : il->GetBasicBlocks()) {
        std::ostringstream blockInfo;
        blockInfo << "Basic block @ 0x" << std::hex << block->GetStart() << ":\n";
        std::cout << blockInfo.str();

        for (size_t instrIndex = block->GetStart(); instrIndex < block->GetEnd(); instrIndex++) {
            MediumLevelILInstruction instr = (*il)[instrIndex];
            vector<InstructionTextToken> tokens;

            il->GetInstructionText(function, function->GetArchitecture(), instrIndex, tokens);
            std::ostringstream instrInfo;
            instrInfo << "\t0x" << std::hex << instr.address << ": ";
            for (const auto& token : tokens) {
                instrInfo << token.text << " ";
            }
            instrInfo << "\n";
            std::cout << instrInfo.str();

            // Track operations on SSA variables
            for (const auto& token : tokens) {
                for (auto& var : vars) {
                    std::string varName = function->GetVariableName(var.var) + "#" + std::to_string(var.version);
                    if (token.text == varName) {
                        // Describe the operation performed on the SSA variable
                        std::ostringstream operationDescription;

                        // Determine the operation based on the opcode
                        switch (instr.operation) {
                            case MLIL_ADD:
                                operationDescription << "Addition ";
                                break;
                            case MLIL_SUB:
                                operationDescription << "Subtraction ";
                                break;
                            case MLIL_MUL:
                                operationDescription << "Multiplication ";
                                break;
                            case MLIL_FDIV:
                                operationDescription << "Division ";
                                break;
                            case MLIL_LOAD:
                                operationDescription << "Load ";
                                break;
                            case MLIL_STORE:
                                operationDescription << "Store ";
                                break;
                            // TODO: incomplete swtch statment, also is always the default unsure why atm"        
                            default:                                                    
                                operationDescription << "Other Operation ";             
                                break;
                        }

                        operationDescription << "on " << token.text << " at addr: 0x" << std::hex << instr.address;
                        variableOps[var].operations.push_back(operationDescription.str());
                    }
                }
            }
        }
    }

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

