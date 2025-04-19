from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView, QWidget, QVBoxLayout, QScrollArea, QComboBox, QPushButton
from PySide6.QtGui import QBrush, QColor
from PySide6.QtCore import Qt
from binaryninja import BinaryView, HighlightColor
from binaryninja.enums import HighlightStandardColor

class SSAVarTab(QTableWidget):
    """The SSA Variable Tab for the bANGR plugin.

    Args:
        QTableWidget (QTableWidget): The inherited QTableWidget from Binary Ninja
    """

    def __init__(self, bv: BinaryView, current_offset: int):
        super().__init__(0, 2)
        self.bv = bv
        self.current_offset = current_offset
        self.setHorizontalHeaderLabels(["Variable", "Taint"])
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

    def populate_variables(self, current_offset:int):
        """Polulate tab with the variables of the current function selected.

        Args:
            bv (BinaryView): The Binaryview of the current analyzed binary.
            current_offset (int): The current code offset selected in the UI.
        """

        self.setRowCount(0)
        if not self.bv: return

        func = next(iter(self.bv.get_functions_containing(current_offset)), None)
        if not func: return
        func = func.mlil_if_available
        if not func: return
        for var in func.ssa_vars:
            self.add_variable_to_table(f"{var.name}#{var.version}", self._get_variable_value(var))
    
    def add_variable_to_table(self, name:str, value:str):
        """Add variable to the VarTab's table.

        Args:
            name (str): The name of the variable to display.
            value (int): The value that the variable holds.
            location (str): The location of the variable on the stack.
        """
        
        row = self.rowCount()
        self.insertRow(row)
        for col, text in enumerate([name, value]):
            item = QTableWidgetItem(text)
            item.setBackground(QBrush(QColor(0, 128, 0)))
            item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            self.setItem(row, col, item)

    @staticmethod
    def _get_variable_value(var):
        return "N/A"
    
    @staticmethod
    def _get_variable_location(var):
        return str(var.storage) if var.storage else "Unknown"
    
class VarTab(QTableWidget):
    """The Variable Tab for the bANGR plugin.

    Args:
        QTableWidget (QTableWidget): The inherited QTableWidget from Binary Ninja
    """

    def __init__(self, bv: BinaryView, current_offset: int):
        """Initialize bANGR Variable Tab.

        Args:
            bv (BinaryView): The Binaryview of the current analyzed binary.
            current_offset (int): The current code offset selected in the UI.
        """

        super().__init__(0, 2)

        self.bv = bv
        self.current_offset = current_offset
        self.setHorizontalHeaderLabels(["Variable", "Taint"])
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        

    def populate_variables(self, current_offset:int):
        """Polulate tab with the variables of the current function selected.

        Args:
            bv (BinaryView): The Binaryview of the current analyzed binary.
            current_offset (int): The current code offset selected in the UI.
        """

        self.setRowCount(0)
        if not self.bv: return

        func = next(iter(self.bv.get_functions_containing(current_offset)), None)
        if not func: return
        func = func.mlil_if_available
        if not func: return

        for var in func.vars:
            self.add_variable_to_table(var.name, self._get_variable_value(var), self._get_variable_location(var))
    
    def add_variable_to_table(self:str, name, value, location):
        """Add variable to the VarTab's table.

        Args:
            name (str): The name of the variable to display.
            value (int): The value that the variable holds.
            location (str): The location of the variable on the stack.
        """

        row = self.rowCount()
        self.insertRow(row)

        for col, text in enumerate([name, value, location]):
            item = QTableWidgetItem(text)
            item.setBackground(QBrush(QColor(128, 0, 0)))
            item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            self.setItem(row, col, item)

    
    @staticmethod
    def _get_variable_value(var):
        return "N/A"
    
    @staticmethod
    def _get_variable_location(var):
        return str(var.storage) if var.storage else "Unknown"
    
class CFPTab(QWidget):
    """The SSA Variable Tab for the bANGR plugin.

    Args:
        QTableWidget (QTableWidget): The inherited QTableWidget from Binary Ninja
    """

    def __init__(self, bv:BinaryView, current_offset:int):
        super().__init__()

        self.bv = bv
        self.current_offset = current_offset
        self.bList = []
        self.dropdowns = []
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        scroll.setWidget(content)
        self.content_layout = QVBoxLayout(content)
        
        self.content_layout.addStretch()
        main_layout = QVBoxLayout(self)
        main_layout.addWidget(scroll)
        self._add_dropdown()

    def _add_dropdown(self, items:list):
        combo = QComboBox()
        combo.addItems(items)

        combo.currentIndexChanged.connect(lambda idx, c=combo: self.on_dropdown_changed(c, idx))
        self.content_layout.addWidget(combo)
        self.bList.append(combo)

    def _on_dropdown_changed(self, combo, index):
        if self.dropdowns.index(combo) < len(self.bList) - 1:
            pass
