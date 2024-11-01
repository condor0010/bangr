#include <inttypes.h>
#include "binaryninjaapi.h"
#include "binaryninjacore.h"
#include "mediumlevelilinstruction.h"
using namespace BinaryNinja;

struct VariableOperations {
    std::vector<std::string> operations;
};

int32_t blockAnalyze(Ref<Function> *function);
