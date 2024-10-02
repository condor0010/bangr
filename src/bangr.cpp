#include <stdio.h>
#include <cinttypes>
#include <typeinfo>
#include <iostream>
#include <vector>

#include "binaryninjacore.h"
#include "binaryninjaapi.h"
#include "mediumlevelilinstruction.h"

using namespace BinaryNinja;
using namespace std;

int main(int argc, char* argv[]) {
    if (argc != 3) {printf("%s <binary> <address>\n", argv[0]);}

    char* binary_arg = argv[1];
    //int addr_arg = 0x00401136;
    int addr_arg = atoi(argv[2]);

    SetBundledPluginDirectory(GetBundledPluginDirectory());
    InitPlugins();

    Ref<BinaryView> bv = BinaryNinja::Load(binary_arg);
    
    std::vector<Ref<Function>> funcs = bv->GetAnalysisFunctionsForAddress(addr_arg);
    
    Ref<Function> function = funcs[0];
    
    Ref<MediumLevelILFunction> il = function->GetMediumLevelIL();
    
    for (auto& block : il->GetBasicBlocks()){
	    printf("%p", block);
    }
    
    return 0;
}

