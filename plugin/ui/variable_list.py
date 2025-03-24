from PySide6.QtSvg import QSvgRenderer
from PySide6.QtCore import Qt
from PySide6.QtGui import QImage, QPainter
from PySide6.QtWidgets import (
    QVBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QTabWidget, QWidget, QLineEdit, QInputDialog
)
from binaryninja import BinaryView, PluginCommand, HighlightStandardColor
from binaryninjaui import SidebarWidget, SidebarWidgetType, SidebarWidgetLocation, SidebarContextSensitivity
import os


class VariableListWidget(SidebarWidget):
    def __init__(self, name, frame, bv: BinaryView):
        super().__init__(name)
        self.bv, self.current_offset = bv, 0
        self.previous_highlighted = []
        self._setup_ui()
        self._populate_variable_list() if bv else None
    
    def _setup_ui(self):
        # Layout and search bar
        layout = QVBoxLayout(self)
        self.search_bar = QLineEdit(placeholderText="Search Variables...")
        self.search_bar.textChanged.connect(self.filter_variables)
        layout.addWidget(self.search_bar)
        
        # Table and tabs
        self.tabWidget = QTabWidget()
        self.variableTable = self._create_table()
        self.tabWidget.addTab(self._wrap_in_widget(self.variableTable), "Variables")
        self.tabWidget.addTab(QWidget(), "SSA Variables")  # SSA tab placeholder
        layout.addWidget(self.tabWidget)

        # Connect table events
        self.variableTable.itemSelectionChanged.connect(self.highlight_instructions)
        self.variableTable.itemDoubleClicked.connect(self.edit_cell)

    def _create_table(self):
        table = QTableWidget(0, 3)
        table.setHorizontalHeaderLabels(["Variable", "Value", "Location"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        return table
    
    @staticmethod
    def _wrap_in_widget(widget):
        container = QWidget()
        container.setLayout(QVBoxLayout(container).addWidget(widget))
        return container
    
    def _populate_variable_list(self):
        self.variableTable.setRowCount(0)
        if not self.bv: return

        func = next(iter(self.bv.get_functions_containing(self.current_offset)), None)
        if not func: return

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
        if location: self.current_offset = location.getOffset()
        self._populate_variable_list()

    def notifyVariableRenamed(self, var, name):
        self._populate_variable_list()
    
    def function_updated(self, view, func):
        self._populate_variable_list()

    def filter_variables(self):
        search_text = self.search_bar.text().lower()
        for row in range(self.variableTable.rowCount()):
            self.variableTable.setRowHidden(row, search_text not in self.variableTable.item(row, 0).text().lower())
    
    def highlight_instructions(self):
        selected_items = self.variableTable.selectedItems()
        if not selected_items or not self.bv: return

        selected_var = selected_items[0].text()
        func = next(iter(self.bv.get_functions_containing(self.current_offset)), None)
        if not func: return
        
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

    def edit_cell(self, item):
        if item.column() == 0 and self.bv:
            new_name, ok = QInputDialog.getText(self, "Rename Variable", "Enter new variable name:", text=item.text())
            if ok and new_name:
                func = self.bv.get_function_at(self.current_offset)
                if func:
                    func.name = new_name
                    item.setText(new_name)


class VariableListWidgetType(SidebarWidgetType):
    name = "Variable List"
    
    def __init__(self):
        path_icon = os.path.join(os.path.dirname(os.path.abspath(__file__)), "RL.svg")
        icon = self._render_svg_icon(path_icon)
        SidebarWidgetType.__init__(self, icon, self.name)

    def _render_svg_icon(self, path_icon):
        renderer = QSvgRenderer(path_icon)
        icon = QImage(56, 56, QImage.Format_ARGB32)
        icon.fill(0xaaA08080)  # Fallback color
        painter = QPainter(icon)
        renderer.render(painter)
        painter.end()
        return icon
    
    def createWidget(self, frame, data):
        return VariableListWidget(self.name, frame, data)


def defaultLocation():
    return SidebarWidgetLocation.RightSidebar

def contextSensitivity():
    return SidebarContextSensitivity.SelfManagedSidebarContext


PluginCommand.register("Show Variable List", "Displays a list of variables and SSA variables", lambda bv: None)

