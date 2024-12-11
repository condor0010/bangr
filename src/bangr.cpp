#include <vector>
#include <string>
#include <cinttypes>
#include <map>
#include <set>
#include <sstream>
#include <iostream>

#include "uitypes.h"
#include "uicontext.h"
#include "viewframe.h"
#include "functionAnalyze.h"
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

    functionAnalyze(&function);

    std::system("pkill bangr");

    return 0;
}

Ref<Function> GetSelectedFunction(BinaryView* bv)
{
    // Get the current active UI context
    UIContext* context = UIContext::activeContext();
    if (!context)
    {
        LogError("No active UI context found.");
        return 0;
    }

    // Get the current view frame
    ViewFrame* viewFrame = context->getCurrentViewFrame();
    if (!viewFrame)
    {
        LogError("No active view frame found.");
        return 0;
    }
    uint64_t currentOffset = viewFrame->getCurrentOffset();
    
    // Find the function at this offset
    std::vector<Ref<Function>> funcs = bv->GetAnalysisFunctionsContainingAddress(currentOffset);
    if (funcs.empty())
    {
        LogInfo("No function is currently selected at this offset.");
        return nullptr;
    }
    else
    {
        LogInfo("Currently selected function: %s", funcs[0]->GetSymbol()->GetFullName().c_str());
        return funcs[0];
    }
}

void RunBangr(BinaryView *view) {
    Ref<Function> function = GetSelectedFunction(view);

    functionAnalyze(&function);

    std::system("pkill bangr");
}

extern "C" {
    BN_DECLARE_CORE_ABI_VERSION
    BN_DECLARE_UI_ABI_VERSION

    BINARYNINJAPLUGIN bool UIPluginInit()
    {
        PluginCommand::Register("Bangr\\Run", "Run Bangr on Currently Selected Function", [](BinaryView* view) {
            // placeholder for the moment
            main(0, nullptr);
		});
        return true;
    }
}

