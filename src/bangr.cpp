#include<stdio.h>
#include <cinttypes>

#include "binaryninjacore.h"
#include "binaryninjaapi.h"
#include "mediumlevelilinstruction.h"

using namespace BinaryNinja;

int main (int argc, char* argv[]) {
	if (argc != 2){return 1;}

	auto binary = argv[1];
	auto addr   = argv[2]

	// plugin setup bs
	SetBundledPluginDirectory(GetBundledPluginDirectory()); 
	InitPlugins();

	// bv is same as in python
	Ref<BinaryView> bv = BinaryNinja::Load(argv[1]);

	// for func in funcs:
	for (auto& func : bv->GetAnalysisFunctionList()) {
		printf("Function at 0x%" PRIx64 ":\n", func->GetStart());
	}
}

