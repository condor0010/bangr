from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView, QComboBox, QSizePolicy
from PySide6.QtGui import QBrush, QColor
from PySide6.QtCore import Qt
from binaryninja import BinaryView
from ..taint_tracker.path_gen import CFGPathExtractor
from binaryninja import BinaryView

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
    
class CFPTab(QComboBox):
    """The SSA Variable Tab for the bANGR plugin.

    Args:
        QTableWidget (QTableWidget): The inherited QTableWidget from Binary Ninja
    """

    def __init__(self, bv:BinaryView, current_offset:int):
        super().__init__()
        text="Select an option..."

        self.bv = bv
        self.current_offset = current_offset
        self.setPlaceholderText(text)

        size_policy = QSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setSizePolicy(size_policy)
        self.setMinimumWidth(0)
        self.setMaximumHeight(50)

        self.currentIndexChanged.connect(self._on_selection_changed)

    def updateContext(self, current_offset:int):
        func = next(iter(self.bv.get_functions_containing(current_offset)), None)
        if func is None: return
        pathgen = CFGPathExtractor(func)
        pathgen.get_paths()
        path_ints = pathgen.get_path_ints()
        path_strs = [str(path) for path in path_ints]
        self.clear()
        self.addItems(path_strs)



    def _on_selection_changed(self, index):

        print(f"[BNComboBox] Selected: {self.itemText(index)}")

    def get_selected_value(self):
        return self.currentText()
