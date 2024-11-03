#include <inttypes.h>
#include <map>
#include "binaryninjaapi.h"
#include "binaryninjacore.h"
#include "mediumlevelilinstruction.h"
using namespace BinaryNinja;

struct VariableOperations {
    std::vector<std::string> operations;
};

std::map<SSAVariable, VariableOperations> * blockAnalyze(Ref<BasicBlock> *basicBlock, std::map<SSAVariable, VariableOperations> *variableOps);
std::map<SSAVariable, VariableOperations> * functionAnalyze(Ref<Function> *function);
