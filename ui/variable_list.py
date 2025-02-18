from PySide6.QtCore import Qt
from PySide6.QtGui import QImage
from binaryninja import BinaryView, PluginCommand, HighlightStandardColor, HighlightColor
from binaryninjaui import *
from PySide6.QtWidgets import (
    QVBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QTabWidget, QWidget
)

class VariableListWidget(SidebarWidget):
    def __init__(self, name, frame, data):
        super().__init__(name)
        self.bv = data
        self.current_offset = 0
        
        self.layout = QVBoxLayout()
        self.tabWidget = QTabWidget()

        # Regular variable table
        self.variableTable = self.createTable()

        # Wrap in QWidget for tab layout
        self.variableTab = QWidget()
        self.ssaTab = QWidget()

        # Add layout to each tab
        var_layout = QVBoxLayout()
        var_layout.addWidget(self.variableTable)
        self.variableTab.setLayout(var_layout)

        ssa_layout = QVBoxLayout()
        self.ssaTab.setLayout(ssa_layout)  # Leave SSA tab empty

        # Add tabs
        self.tabWidget.addTab(self.variableTab, "Variables")
        self.tabWidget.addTab(self.ssaTab, "SSA Variables")

        self.layout.addWidget(self.tabWidget)
        self.setLayout(self.layout)

        if self.bv:
            self.populateVariableList()
            self.bv.register_notification(self)

        self.variableTable.itemSelectionChanged.connect(self.highlight_variable_usage)

    def createTable(self):
        """ Creates a QTableWidget with three columns. """
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Variable", "Value", "Location"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        return table

    def populateVariableList(self):
        """ Populates the regular variable list. """
        self.variableTable.setRowCount(0)
        
        if not self.bv:
            return

        func_list = self.bv.get_functions_containing(self.current_offset)
        if not func_list:
            return

        func = func_list[0]

        # Populate normal variables
        for var in func.vars:
            self.addVariableToTable(self.variableTable, var.name, self.get_variable_value(func, var), self.get_variable_location(var))

    def addVariableToTable(self, table, name, value, location):
        """ Adds a variable to the specified table. """
        row_position = table.rowCount()
        table.insertRow(row_position)

        name_item = QTableWidgetItem(name)
        name_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        table.setItem(row_position, 0, name_item)

        value_item = QTableWidgetItem(value)
        value_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        table.setItem(row_position, 1, value_item)

        location_item = QTableWidgetItem(location)
        location_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        table.setItem(row_position, 2, location_item)

    def get_variable_value(self, func, var):
        """ Placeholder for getting variable values. """
        return "N/A"  # Modify this if you can extract values from BN

    def get_variable_location(self, var):
        """ Returns the memory address or register name of the variable. """
        if var.storage:
            return str(var.storage)
        return "Unknown"

    def notifyViewLocationChanged(self, view, location):
        """ Updates the variable lists when the cursor moves. """
        if location:
            self.current_offset = location.getOffset()
            self.populateVariableList()

    def notifyVariableRenamed(self, var, name):
        """ Updates the table when a variable is renamed. """
        self.populateVariableList()
    
    def function_updated(self, view, func):
        """ Called when a function is updated. """
        self.populateVariableList()
    
    def function_update_requested(self, view, func):
        """ Called when a function update is requested. """
        self.populateVariableList()
    
    def undo_entry_added(self, view, entry):
        """ Called when an undo entry is added, which may include variable renaming. """
        self.populateVariableList()

    def highlight_variable_usage(self):
        """ Highlights lines where the selected variable is used. """
        selected_items = self.variableTable.selectedItems()
        if not selected_items:
            return
        
        variable_name = selected_items[0].text()
        
        func_list = self.bv.get_functions_containing(self.current_offset)
        if not func_list:
            return
        
        func = func_list[0]
        for block in func.low_level_il:
            for instr in block:
                # Check if the instruction uses the variable by checking if the variable name is in the instruction
                if variable_name in str(instr):
                    # Highlight the instruction in green
                    blocks = self.bv.get_basic_blocks_at(instr.address)
                    for block in blocks:
                        block.set_auto_highlight(HighlightColor(HighlightStandardColor.GreenHighlightColor, alpha=128))
                        block.function.set_auto_instr_highlight(instr.address, HighlightStandardColor.GreenHighlightColor)

class VariableListWidgetType(SidebarWidgetType):
    name = "Variable List"

    def __init__(self):
        image = QImage()
        super().__init__(image, VariableListWidgetType.name)

    def createWidget(self, frame, data):
        return VariableListWidget(self.name, frame, data)

def defaultLocation(self):
    if hasattr(SidebarWidgetLocation, "RightSidebar"):
        return SidebarWidgetLocation.RightSidebar
    return SidebarWidgetLocation.LocalSidebar  # Fallback if RightSidebar doesn't exist

def contextSensitivity(self):
    return SidebarContextSensitivity.SelfManagedSidebarContext

PluginCommand.register("Show Variable List", "Displays a list of variables and SSA variables", lambda bv: None)

