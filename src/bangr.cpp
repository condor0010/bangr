#include<stdio.h>
#include <cinttypes>
#include <typeinfo>

#include "binaryninjacore.h"
#include "binaryninjaapi.h"
#include "mediumlevelilinstruction.h"

using namespace BinaryNinja;
#include <iostream>
using namespace std;

int main (int argc, char* argv[]) {
	if(argc != 3){ printf("%s <binary> <address>\n", argv[0]); return 1;}

	char* binary_arg = argv[1];
	int  addr_arg   = atoi(argv[2]);

	SetBundledPluginDirectory(GetBundledPluginDirectory());
	InitPlugins();

	Ref<BinaryView> bv = BinaryNinja::Load(binary_arg);
	for (auto& func : bv->GetAnalysisFunctionList()){
		Ref<MediumLevelILFunction> il = func->GetMediumLevelIL();
	}
	
	
	//std::vector<Ref<Function>> func = bv->GetAnalysisFunctionsForAddress(addr_arg);
	//Ref<MediumLevelILFunction> il = func->GetMediumLevelIL();
	
}
