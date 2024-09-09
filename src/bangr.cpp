#include<stdio.h>
#include <cinttypes>

#include "binaryninjacore.h"
#include "binaryninjaapi.h"
#include "mediumlevelilinstruction.h"

using namespace BinaryNinja;

int main (int argc, char* argv[]) {
	if(argc != 3){ printf("%s <binary> <address>\n", argv[0]); return 1;}

	auto binary_arg = argv[1];
	auto addr_arg   = argv[2];

	// plugin setup bs
	SetBundledPluginDirectory(GetBundledPluginDirectory());
	InitPlugins();

	// bv is same as in python
	Ref<BinaryView> bv = BinaryNinja::Load(binary_arg);

	// for func in funcs:
	for (auto& func : bv->GetAnalysisFunctionList()) {
		printf("Function at 0x%" PRIx64 ":\n", func->GetStart());
	}
}
