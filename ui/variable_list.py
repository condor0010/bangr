from PySide6.QtCore import Qt
from PySide6.QtGui import QImage
from PySide6.QtWidgets import (
    QVBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QTabWidget, QWidget, QLineEdit
)
from binaryninja import BinaryView, PluginCommand, HighlightStandardColor
from binaryninjaui import SidebarWidget, SidebarWidgetType, SidebarWidgetLocation

class VariableListWidget(SidebarWidget):
    def __init__(self, name, frame, bv: BinaryView):
        super().__init__(name)
        self.bv = bv
        self.current_offset = 0
        self.previous_highlighted = []
        self._setup_ui()
        if bv:
            self._initialize_data()
    
    def _setup_ui(self):
        self.layout = QVBoxLayout(self)
        
        # Add a search bar
        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search Variables...")
        self.search_bar.textChanged.connect(self.filter_variables)
        self.layout.addWidget(self.search_bar)
        
        # Create tabs and tables
        self.tabWidget = QTabWidget()
        self.variableTable = self._create_table()
        
        self.variableTab = self._wrap_in_widget(self.variableTable)
        self.ssaTab = QWidget()
        
        self.tabWidget.addTab(self.variableTab, "Variables")
        self.tabWidget.addTab(self.ssaTab, "SSA Variables")
        self.layout.addWidget(self.tabWidget)
        
        # Connect the selection change signal
        self.variableTable.itemSelectionChanged.connect(self.highlight_instructions)
        self.variableTable.itemDoubleClicked.connect(self.edit_cell)
    
    def _initialize_data(self):
        self._populate_variable_list()
    
    def _create_table(self):
        table = QTableWidget(0, 3)
        table.setHorizontalHeaderLabels(["Variable", "Value", "Location"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        return table
    
    @staticmethod
    def _wrap_in_widget(widget):
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.addWidget(widget)
        return container
    
    def _populate_variable_list(self):
        self.variableTable.setRowCount(0)
        if not self.bv:
            return
        
        func = next(iter(self.bv.get_functions_containing(self.current_offset)), None)
        if not func:
            return
        
        for var in func.vars:
            self._add_variable_to_table(var.name, self._get_variable_value(var), self._get_variable_location(var))
    
    def _add_variable_to_table(self, name, value, location):
        row = self.variableTable.rowCount()
        self.variableTable.insertRow(row)
        for col, text in enumerate([name, value, location]):
            item = QTableWidgetItem(text)
            item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsEditable)
            self.variableTable.setItem(row, col, item)
    
    @staticmethod
    def _get_variable_value(var):
        return "N/A"
    
    @staticmethod
    def _get_variable_location(var):
        return str(var.storage) if var.storage else "Unknown"
    
    def notifyViewLocationChanged(self, view, location):
        if location:
            self.current_offset = location.getOffset()
            self._populate_variable_list()
    
    def notifyVariableRenamed(self, var, name):
        self._populate_variable_list()
    
    def function_updated(self, view, func):
        self._populate_variable_list()
    
    def function_update_requested(self, view, func):
        self._populate_variable_list()
    
    def undo_entry_added(self, view, entry):
        self._populate_variable_list()
    
    def filter_variables(self):
        search_text = self.search_bar.text().lower()
        
        for row in range(self.variableTable.rowCount()):
            variable_name = self.variableTable.item(row, 0).text().lower()
            if search_text in variable_name:
                self.variableTable.setRowHidden(row, False)
            else:
                self.variableTable.setRowHidden(row, True)
    
    def highlight_instructions(self):
        selected_items = self.variableTable.selectedItems()
        if not selected_items or not self.bv:
            return
        
        selected_var = selected_items[0].text()
        func = next(iter(self.bv.get_functions_containing(self.current_offset)), None)
        if not func:
            return
        
        # Remove previous highlights
        for addr in self.previous_highlighted:
            func.set_user_instr_highlight(addr, HighlightStandardColor.NoHighlightColor)
        self.previous_highlighted.clear()
        
        # Apply new highlights
        for block in func.basic_blocks:
            for instr in block.get_disassembly_text():
                if any(selected_var in token.text for token in instr.tokens):
                    func.set_user_instr_highlight(instr.address, HighlightStandardColor.BlueHighlightColor)
                    self.previous_highlighted.append(instr.address)
    
    def edit_cell(self, item): # tis broken
        if item.column() == 0 and self.bv:
            old_name = item.text()
            new_name, ok = QInputDialog.getText(self, "Rename Function", "Enter new function name:", text=old_name)
            if ok and new_name:
                func = self.bv.get_function_at(self.current_offset)
                if func:
                    func.name = new_name
                    item.setText(new_name)

class VariableListWidgetType(SidebarWidgetType):
    name = "Variable List"

    def __init__(self):
        super().__init__(QImage(), self.name)
    
    def createWidget(self, frame, data):
        return VariableListWidget(self.name, frame, data)

def defaultLocation():
    return getattr(SidebarWidgetLocation, "RightSidebar", SidebarWidgetLocation.LocalSidebar)

def contextSensitivity():
    return SidebarContextSensitivity.SelfManagedSidebarContext

# Register the plugin command
PluginCommand.register("Show Variable List", "Displays a list of variables and SSA variables", lambda bv: None)

