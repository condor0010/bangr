# sidebar_widget.py
from PySide6.QtWidgets import QVBoxLayout, QTabWidget, QWidget, QLineEdit, QTableWidget, QTableWidgetItem, QHeaderView, QInputDialog
from binaryninja import BinaryView
from .table_widget import VariableTable
from .tabs import SSAPlaceholderTab
from .utils import filter_variables

class VariableListWidget(SidebarWidget):
    def __init__(self, name, frame, bv: BinaryView):
        super().__init__(name)
        self.bv, self.current_offset = bv, 0
        self.previous_highlighted = []
        self._setup_ui()
        self._populate_variable_list() if bv else None
    
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        self.search_bar = QLineEdit(placeholderText="Search Variables...")
        self.search_bar.textChanged.connect(self.filter_variables)
        layout.addWidget(self.search_bar)
        
        self.tabWidget = QTabWidget()
        self.variableTable = VariableTable(self.bv, self.current_offset)
        self.tabWidget.addTab(self.variableTable, "Variables")
        self.tabWidget.addTab(SSAPlaceholderTab(), "SSA Variables")
        layout.addWidget(self.tabWidget)

        self.variableTable.itemSelectionChanged.connect(self.highlight_instructions)
        self.variableTable.itemDoubleClicked.connect(self.edit_cell)

    def _populate_variable_list(self):
        self.variableTable.populate_variables(self.bv, self.current_offset)

    def filter_variables(self):
        filter_variables(self.search_bar, self.variableTable)

    def highlight_instructions(self):
        selected_items = self.variableTable.selectedItems()
        if not selected_items or not self.bv: return

        selected_var = selected_items[0].text()
        func = next(iter(self.bv.get_functions_containing(self.current_offset)), None)
        if not func: return

        for addr in self.previous_highlighted:
            func.set_user_instr_highlight(addr, HighlightStandardColor.NoHighlightColor)
        self.previous_highlighted.clear()

        for block in func.basic_blocks:
            for instr in block.get_disassembly_text():
                if any(selected_var in token.text for token in instr.tokens):
                    func.set_user_instr_highlight(instr.address, HighlightStandardColor.BlueHighlightColor)
                    self.previous_highlighted.append(instr.address)

    def edit_cell(self, item):
        if item.column() == 0 and self.bv:
            new_name, ok = QInputDialog.getText(self, "Rename Variable", "Enter new variable name:", text=item.text())
            if ok and new_name:
                func = self.bv.get_function_at(self.current_offset)
                if func:
                    func.name = new_name
                    item.setText(new_name)

