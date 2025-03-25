# utils.py
from PySide6.QtWidgets import QTableWidget

def filter_variables(search_bar, variable_table: QTableWidget):
    search_text = search_bar.text().lower()
    for row in range(variable_table.rowCount()):
        variable_table.setRowHidden(row, search_text not in variable_table.item(row, 0).text().lower())

