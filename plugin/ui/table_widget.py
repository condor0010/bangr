# table_widget.py
from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
from binaryninja import BinaryView

class VariableTable(QTableWidget):
    def __init__(self, bv: BinaryView, current_offset: int):
        super().__init__(0, 3)
        self.bv = bv
        self.current_offset = current_offset
        self.setHorizontalHeaderLabels(["Variable", "Value", "Location"])
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

    def populate_variables(self, bv, current_offset):
        self.setRowCount(0)
        if not bv: return

        func = next(iter(bv.get_functions_containing(current_offset)), None)
        if not func: return

        for var in func.vars:
            self.add_variable_to_table(var.name, self._get_variable_value(var), self._get_variable_location(var))
    
    def add_variable_to_table(self, name, value, location):
        row = self.rowCount()
        self.insertRow(row)
        for col, text in enumerate([name, value, location]):
            item = QTableWidgetItem(text)
            item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsEditable)
            self.setItem(row, col, item)
    
    @staticmethod
    def _get_variable_value(var):
        return "N/A"
    
    @staticmethod
    def _get_variable_location(var):
        return str(var.storage) if var.storage else "Unknown"

