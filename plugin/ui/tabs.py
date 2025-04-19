from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView, QWidget
from PySide6.QtCore import Qt
from binaryninja import BinaryView

class SSAPlaceholderTab(QTableWidget):
    def __init__(self, bv: BinaryView, current_offset: int):
        super().__init__(0, 2)
        self.bv = bv
        self.current_offset = current_offset
        self.setHorizontalHeaderLabels(["Variable", "Value"])
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

    def populate_variables(self, bv, current_offset):
        self.setRowCount(0)
        if not bv: return

        func = next(iter(bv.get_functions_containing(current_offset)), None)
        if not func: return
        func = func.mlil_if_available
        if not func: return
        for var in func.ssa_vars:
            self.add_variable_to_table(f"{var.name}#{var.version}", self._get_variable_value(var))
    
    def add_variable_to_table(self, name, value):
        row = self.rowCount()
        self.insertRow(row)
        for col, text in enumerate([name, value]):
            item = QTableWidgetItem(text)
            item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsEditable)
            self.setItem(row, col, item)
    
    @staticmethod
    def _get_variable_value(var):
        return "N/A"
    
    @staticmethod
    def _get_variable_location(var):
        return str(var.storage) if var.storage else "Unknown"

