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
                            case MLIL_NOP:
                                operationDescription << "MLIL_NOP ";
                                break;
                            case MLIL_SET_VAR:
                                operationDescription << "MLIL_SET_VAR ";
                                break;
                            case MLIL_SET_VAR_FIELD:
                                operationDescription << "MLIL_SET_VAR_FIELD ";
                                break;
                            case MLIL_SET_VAR_SPLIT:
                                operationDescription << "MLIL_SET_VAR_SPLIT ";
                                break;
                            case MLIL_LOAD:
                                operationDescription << "MLIL_LOAD ";
                                break;
                            case MLIL_LOAD_STRUCT:
                                operationDescription << "MLIL_LOAD_STRUCT ";
                                break;
                            case MLIL_STORE:
                                operationDescription << "MLIL_STORE ";
                                break;
                            case MLIL_STORE_STRUCT:
                                operationDescription << "MLIL_STORE_STRUCT ";
                                break;
                            case MLIL_VAR:
                                operationDescription << "MLIL_VAR ";
                                break;
                            case MLIL_VAR_FIELD:
                                operationDescription << "MLIL_VAR_FIELD ";
                                break;
                            case MLIL_VAR_SPLIT:
                                operationDescription << "MLIL_VAR_SPLIT ";
                                break;
                            case MLIL_ADDRESS_OF:
                                operationDescription << "MLIL_ADDRESS_OF ";
                                break;
                            case MLIL_ADDRESS_OF_FIELD:
                                operationDescription << "MLIL_ADDRESS_OF_FIELD ";
                                break;
                            case MLIL_CONST:
                                operationDescription << "MLIL_CONST ";
                                break;
                            case MLIL_CONST_DATA:
                                operationDescription << "MLIL_CONST_DATA ";
                                break;
                            case MLIL_CONST_PTR:
                                operationDescription << "MLIL_CONST_PTR ";
                                break;
                            case MLIL_EXTERN_PTR:
                                operationDescription << "MLIL_EXTERN_PTR ";
                                break;
                            case MLIL_FLOAT_CONST:
                                operationDescription << "MLIL_FLOAT_CONST ";
                                break;
                            case MLIL_IMPORT:
                                operationDescription << "MLIL_IMPORT ";
                                break;
                            case MLIL_ADD:
                                operationDescription << "MLIL_ADD ";
                                break;
                            case MLIL_ADC:
                                operationDescription << "MLIL_ADC ";
                                break;
                            case MLIL_SUB:
                                operationDescription << "MLIL_SUB ";
                                break;
                            case MLIL_SBB:
                                operationDescription << "MLIL_SBB ";
                                break;
                            case MLIL_AND:
                                operationDescription << "MLIL_AND ";
                                break;
                            case MLIL_OR:
                                operationDescription << "MLIL_OR ";
                                break;
                            case MLIL_XOR:
                                operationDescription << "MLIL_XOR ";
                                break;
                            case MLIL_LSL:
                                operationDescription << "MLIL_LSL ";
                                break;
                            case MLIL_LSR:
                                operationDescription << "MLIL_LSR ";
                                break;
                            case MLIL_ASR:
                                operationDescription << "MLIL_ASR ";
                                break;
                            case MLIL_ROL:
                                operationDescription << "MLIL_ROL ";
                                break;
                            case MLIL_RLC:
                                operationDescription << "MLIL_RLC ";
                                break;
                            case MLIL_ROR:
                                operationDescription << "MLIL_ROR ";
                                break;
                            case MLIL_RRC:
                                operationDescription << "MLIL_RRC ";
                                break;
                            case MLIL_MUL:
                                operationDescription << "MLIL_MUL ";
                                break;
                            case MLIL_MULU_DP:
                                operationDescription << "MLIL_MULU_DP ";
                                break;
                            case MLIL_MULS_DP:
                                operationDescription << "MLIL_MULS_DP ";
                                break;
                            case MLIL_DIVU:
                                operationDescription << "MLIL_DIVU ";
                                break;
                            case MLIL_DIVU_DP:
                                operationDescription << "MLIL_DIVU_DP ";
                                break;
                            case MLIL_DIVS:
                                operationDescription << "MLIL_DIVS ";
                                break;
                            case MLIL_DIVS_DP:
                                operationDescription << "MLIL_DIVS_DP ";
                                break;
                            case MLIL_MODU:
                                operationDescription << "MLIL_MODU ";
                                break;
                            case MLIL_MODU_DP:
                                operationDescription << "MLIL_MODU_DP ";
                                break;
                            case MLIL_MODS:
                                operationDescription << "MLIL_MODS ";
                                break;
                            case MLIL_MODS_DP:
                                operationDescription << "MLIL_MODS_DP ";
                                break;
                            case MLIL_NEG:
                                operationDescription << "MLIL_NEG ";
                                break;
                            case MLIL_NOT:
                                operationDescription << "MLIL_NOT ";
                                break;
                            case MLIL_SX:
                                operationDescription << "MLIL_SX ";
                                break;
                            case MLIL_ZX:
                                operationDescription << "MLIL_ZX ";
                                break;
                            case MLIL_LOW_PART:
                                operationDescription << "MLIL_LOW_PART ";
                                break;
                            case MLIL_JUMP:
                                operationDescription << "MLIL_JUMP ";
                                break;
                            case MLIL_JUMP_TO:
                                operationDescription << "MLIL_JUMP_TO ";
                                break;
                            case MLIL_RET_HINT:
                                operationDescription << "MLIL_RET_HINT ";
                                break;
                            case MLIL_CALL:
                                operationDescription << "MLIL_CALL ";
                                break;
                            case MLIL_CALL_UNTYPED:
                                operationDescription << "MLIL_CALL_UNTYPED ";
                                break;
                            case MLIL_CALL_OUTPUT:
                                operationDescription << "MLIL_CALL_OUTPUT ";
                                break;
                            case MLIL_CALL_PARAM:
                                operationDescription << "MLIL_CALL_PARAM ";
                                break;
                            case MLIL_SEPARATE_PARAM_LIST:
                                operationDescription << "MLIL_SEPARATE_PARAM_LIST ";
                                break;
                            case MLIL_SHARED_PARAM_SLOT:
                                operationDescription << "MLIL_SHARED_PARAM_SLOT ";
                                break;
                            case MLIL_RET:
                                operationDescription << "MLIL_RET ";
                                break;
                            case MLIL_NORET:
                                operationDescription << "MLIL_NORET ";
                                break;
                            case MLIL_IF:
                                operationDescription << "MLIL_IF ";
                                break;
                            case MLIL_GOTO:
                                operationDescription << "MLIL_GOTO ";
                                break;
                            case MLIL_CMP_E:
                                operationDescription << "MLIL_CMP_E ";
                                break;
                            case MLIL_CMP_NE:
                                operationDescription << "MLIL_CMP_NE ";
                                break;
                            case MLIL_CMP_SLT:
                                operationDescription << "MLIL_CMP_SLT ";
                                break;
                            case MLIL_CMP_ULT:
                                operationDescription << "MLIL_CMP_ULT ";
                                break;
                            case MLIL_CMP_SLE:
                                operationDescription << "MLIL_CMP_SLE ";
                                break;
                            case MLIL_CMP_ULE:
                                operationDescription << "MLIL_CMP_ULE ";
                                break;
                            case MLIL_CMP_SGE:
                                operationDescription << "MLIL_CMP_SGE ";
                                break;
                            case MLIL_CMP_UGE:
                                operationDescription << "MLIL_CMP_UGE ";
                                break;
                            case MLIL_CMP_SGT:
                                operationDescription << "MLIL_CMP_SGT ";
                                break;
                            case MLIL_CMP_UGT:
                                operationDescription << "MLIL_CMP_UGT ";
                                break;
                            case MLIL_TEST_BIT:
                                operationDescription << "MLIL_TEST_BIT ";
                                break;
                            case MLIL_BOOL_TO_INT:
                                operationDescription << "MLIL_BOOL_TO_INT ";
                                break;
                            case MLIL_ADD_OVERFLOW:
                                operationDescription << "MLIL_ADD_OVERFLOW ";
                                break;
                            case MLIL_SYSCALL:
                                operationDescription << "MLIL_SYSCALL ";
                                break;
                            case MLIL_SYSCALL_UNTYPED:
                                operationDescription << "MLIL_SYSCALL_UNTYPED ";
                                break;
                            case MLIL_TAILCALL:
                                operationDescription << "MLIL_TAILCALL ";
                                break;
                            case MLIL_TAILCALL_UNTYPED:
                                operationDescription << "MLIL_TAILCALL_UNTYPED ";
                                break;
                            case MLIL_INTRINSIC:
                                operationDescription << "MLIL_INTRINSIC ";
                                break;
                            case MLIL_FREE_VAR_SLOT:
                                operationDescription << "MLIL_FREE_VAR_SLOT ";
                                break;
                            case MLIL_BP:
                                operationDescription << "MLIL_BP ";
                                break;
                            case MLIL_TRAP:
                                operationDescription << "MLIL_TRAP ";
                                break;
                            case MLIL_UNDEF:
                                operationDescription << "MLIL_UNDEF ";
                                break;
                            case MLIL_UNIMPL:
                                operationDescription << "MLIL_UNIMPL ";
                                break;
                            case MLIL_UNIMPL_MEM:
                                operationDescription << "MLIL_UNIMPL_MEM ";
                                break;
                            case MLIL_FADD:
                                operationDescription << "MLIL_FADD ";
                                break;
                            case MLIL_FSUB:
                                operationDescription << "MLIL_FSUB ";
                                break;
                            case MLIL_FMUL:
                                operationDescription << "MLIL_FMUL ";
                                break;
                            case MLIL_FDIV:
                                operationDescription << "MLIL_FDIV ";
                                break;
                            case MLIL_FSQRT:
                                operationDescription << "MLIL_FSQRT ";
                                break;
                            case MLIL_FNEG:
                                operationDescription << "MLIL_FNEG ";
                                break;
                            case MLIL_FABS:
                                operationDescription << "MLIL_FABS ";
                                break;
                            case MLIL_FLOAT_TO_INT:
                                operationDescription << "MLIL_FLOAT_TO_INT ";
                                break;
                            case MLIL_INT_TO_FLOAT:
                                operationDescription << "MLIL_INT_TO_FLOAT ";
                                break;
                            case MLIL_FLOAT_CONV:
                                operationDescription << "MLIL_FLOAT_CONV ";
                                break;
                            case MLIL_ROUND_TO_INT:
                                operationDescription << "MLIL_ROUND_TO_INT ";
                                break;
                            case MLIL_FLOOR:
                                operationDescription << "MLIL_FLOOR ";
                                break;
                            case MLIL_CEIL:
                                operationDescription << "MLIL_CEIL ";
                                break;
                            case MLIL_FTRUNC:
                                operationDescription << "MLIL_FTRUNC ";
                                break;
                            case MLIL_FCMP_E:
                                operationDescription << "MLIL_FCMP_E ";
                                break;
                            case MLIL_FCMP_NE:
                                operationDescription << "MLIL_FCMP_NE ";
                                break;
                            case MLIL_FCMP_LT:
                                operationDescription << "MLIL_FCMP_LT ";
                                break;
                            case MLIL_FCMP_LE:
                                operationDescription << "MLIL_FCMP_LE ";
                                break;
                            case MLIL_FCMP_GE:
                                operationDescription << "MLIL_FCMP_GE ";
                                break;
                            case MLIL_FCMP_GT:
                                operationDescription << "MLIL_FCMP_GT ";
                                break;
                            case MLIL_FCMP_O:
                                operationDescription << "MLIL_FCMP_O ";
                                break;
                            case MLIL_FCMP_UO:
                                operationDescription << "MLIL_FCMP_UO ";
                                break;
                            case MLIL_SET_VAR_SSA:
                                operationDescription << "MLIL_SET_VAR_SSA ";
                                break;
                            case MLIL_SET_VAR_SSA_FIELD:
                                operationDescription << "MLIL_SET_VAR_SSA_FIELD ";
                                break;
                            case MLIL_SET_VAR_SPLIT_SSA:
                                operationDescription << "MLIL_SET_VAR_SPLIT_SSA ";
                                break;
                            case MLIL_SET_VAR_ALIASED:
                                operationDescription << "MLIL_SET_VAR_ALIASED ";
                                break;
                            case MLIL_SET_VAR_ALIASED_FIELD:
                                operationDescription << "MLIL_SET_VAR_ALIASED_FIELD ";
                                break;
                            case MLIL_VAR_SSA:
                                operationDescription << "MLIL_VAR_SSA ";
                                break;
                            case MLIL_VAR_SSA_FIELD:
                                operationDescription << "MLIL_VAR_SSA_FIELD ";
                                break;
                            case MLIL_VAR_ALIASED:
                                operationDescription << "MLIL_VAR_ALIASED ";
                                break;
                            case MLIL_VAR_ALIASED_FIELD:
                                operationDescription << "MLIL_VAR_ALIASED_FIELD ";
                                break;
                            case MLIL_VAR_SPLIT_SSA:
                                operationDescription << "MLIL_VAR_SPLIT_SSA ";
                                break;
                            case MLIL_CALL_SSA:
                                operationDescription << "MLIL_CALL_SSA ";
                                break;
                            case MLIL_CALL_UNTYPED_SSA:
                                operationDescription << "MLIL_CALL_UNTYPED_SSA ";
                                break;
                            case MLIL_SYSCALL_SSA:
                                operationDescription << "MLIL_SYSCALL_SSA ";
                                break;
                            case MLIL_SYSCALL_UNTYPED_SSA:
                                operationDescription << "MLIL_SYSCALL_UNTYPED_SSA ";
                                break;
                            case MLIL_TAILCALL_SSA:
                                operationDescription << "MLIL_TAILCALL_SSA ";
                                break;
                            case MLIL_TAILCALL_UNTYPED_SSA:
                                operationDescription << "MLIL_TAILCALL_UNTYPED_SSA ";
                                break;
                            case MLIL_CALL_PARAM_SSA:
                                operationDescription << "MLIL_CALL_PARAM_SSA ";
                                break;
                            case MLIL_CALL_OUTPUT_SSA:
                                operationDescription << "MLIL_CALL_OUTPUT_SSA ";
                                break;
                            case MLIL_MEMORY_INTRINSIC_OUTPUT_SSA:
                                operationDescription << "MLIL_MEMORY_INTRINSIC_OUTPUT_SSA ";
                                break;
                            case MLIL_LOAD_SSA:
                                operationDescription << "MLIL_LOAD_SSA ";
                                break;
                            case MLIL_LOAD_STRUCT_SSA:
                                operationDescription << "MLIL_LOAD_STRUCT_SSA ";
                                break;
                            case MLIL_STORE_SSA:
                                operationDescription << "MLIL_STORE_SSA ";
                                break;
                            case MLIL_STORE_STRUCT_SSA:
                                operationDescription << "MLIL_STORE_STRUCT_SSA ";
                                break;
                            case MLIL_INTRINSIC_SSA:
                                operationDescription << "MLIL_INTRINSIC_SSA ";
                                break;
                            case MLIL_MEMORY_INTRINSIC_SSA:
                                operationDescription << "MLIL_MEMORY_INTRINSIC_SSA ";
                                break;
                            case MLIL_FREE_VAR_SLOT_SSA:
                                operationDescription << "MLIL_FREE_VAR_SLOT_SSA ";
                                break;
                            case MLIL_VAR_PHI:
                                operationDescription << "MLIL_VAR_PHI ";
                                break;
                            case MLIL_MEM_PHI:
                                operationDescription << "MLIL_MEM_PHI ";
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
    std::system("pkill bangr");
    return 0;
}

