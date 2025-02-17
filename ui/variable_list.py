from PySide6.QtCore import Qt
from PySide6.QtGui import QImage
from binaryninja import BinaryView, PluginCommand
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
        self.ssaVariableTable = self.createTable()

        # Wrap in QWidget for tab layout
        self.variableTab = QWidget()
        self.ssaTab = QWidget()

        # Add layout to each tab
        var_layout = QVBoxLayout()
        var_layout.addWidget(self.variableTable)
        self.variableTab.setLayout(var_layout)

        ssa_layout = QVBoxLayout()
        ssa_layout.addWidget(self.ssaVariableTable)
        self.ssaTab.setLayout(ssa_layout)

        # Add tabs
        self.tabWidget.addTab(self.variableTab, "Variables")
        self.tabWidget.addTab(self.ssaTab, "SSA Variables")

        self.layout.addWidget(self.tabWidget)
        self.setLayout(self.layout)

        if self.bv:
            self.populateVariableList()

    def createTable(self):
        """ Creates a QTableWidget with two columns. """
        table = QTableWidget()
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(["Variable", "Value"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        return table

    def populateVariableList(self):
        """ Populates both regular and SSA variable lists. """
        self.variableTable.setRowCount(0)
        self.ssaVariableTable.setRowCount(0)
        
        if not self.bv:
            return

        func_list = self.bv.get_functions_containing(self.current_offset)
        if not func_list:
            return

        func = func_list[0]

        # Populate normal variables
        for var in func.vars:
            self.addVariableToTable(self.variableTable, var.name, self.get_variable_value(func, var))

        # Populate SSA variables
        if func.ssa_form:
            for ssa_var in func.ssa_form.vars:
                self.addVariableToTable(self.ssaVariableTable, str(ssa_var), self.get_variable_value(func, ssa_var))

    def addVariableToTable(self, table, name, value):
        """ Adds a variable to the specified table. """
        row_position = table.rowCount()
        table.insertRow(row_position)

        name_item = QTableWidgetItem(name)
        name_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        table.setItem(row_position, 0, name_item)

        value_item = QTableWidgetItem(value)
        value_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        table.setItem(row_position, 1, value_item)

    def get_variable_value(self, func, var):
        """ Placeholder for getting variable values. """
        return "N/A"  # Modify this if you can extract values from BN

    def notifyViewLocationChanged(self, view, location):
        """ Updates the variable lists when the cursor moves. """
        if location:
            self.current_offset = location.getOffset()
            self.populateVariableList()

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

