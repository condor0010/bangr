from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView, QWidget, QVBoxLayout, QScrollArea, QComboBox, QPushButton
from PySide6.QtGui import QBrush, QColor
from PySide6.QtCore import Qt
from binaryninja import BasicBlock, BinaryView, HighlightColor
from binaryninja.enums import HighlightStandardColor
from ..taint_tracker.path_gen import CFGPathExtractor

class SSAVarTab(QTableWidget):
    """The SSA Variable Tab for the bANGR plugin.

    Args:
        QTableWidget (QTableWidget): The inherited QTableWidget from Binary Ninja
    """

    def __init__(self, bv: BinaryView):
        super().__init__(0, 2)
        self.bv = bv
        self.current_offset = 0
        self.setHorizontalHeaderLabels(["Variable", "Taint"])
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

    def populate_variables(self, current_offset:int):
        """Polulate tab with the variables of the current function selected.

        Args:
            bv (BinaryView): The Binaryview of the current analyzed binary.
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

    def __init__(self, bv: BinaryView):
        """Initialize bANGR Variable Tab.

        Args:
            bv (BinaryView): The Binaryview of the current analyzed binary.
        """

        super().__init__(0, 2)

        self.bv = bv
        self.current_offset = 0
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

    def __init__(self, bv:BinaryView):
        super().__init__()

        self.bv = bv
        self.last_temp_highlight = None
        self.block_list = []
        self.dropdowns = []

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)

        content = QWidget()
        exec_button = QPushButton(text="Execute")
        exec_button.pressed.connect(self.execute)
        scroll.setWidget(content)
        self.content_layout = QVBoxLayout(content)
        self.content_layout.setAlignment(Qt.AlignTop)
        self.content_layout.addWidget(exec_button)

        main_layout = QVBoxLayout(self)
        main_layout.addWidget(scroll)
    
    def execute(self):
        print("Execute!")
    
    def _remove_dropdowns(self, number_of_dropdowns:int):
        for _ in range(number_of_dropdowns):
            self._remove_dropdown(self.dropdowns.pop())
            self.block_list.pop().set_auto_highlight(HighlightColor(HighlightStandardColor.NoHighlightColor))
        if len(self.block_list) == 1:
            self.unhighlight_root()

    def _remove_dropdown(self, combo: QComboBox):
        self.content_layout.removeWidget(combo)
        combo.setParent(None)
        combo.deleteLater()

    def update_CFP(self, current_offset):
        self._remove_dropdowns(len(self.dropdowns))
        self.current_offset = current_offset

        func = next(iter(self.bv.get_functions_containing(current_offset)), None)
        if not func: return
        func = func.mlil_if_available
        if not func: return

        self.block_list = [func.basic_blocks[0]]
        
        drop_items = ["Select an Option..."]
        drop_items.extend([f"0x{path.target[0].address:x}" for path in self.block_list[0].outgoing_edges])
        
        self._add_dropdown(drop_items)
        
    def highlight_root(self):
        self.block_list[0].set_auto_highlight(HighlightColor(HighlightStandardColor.BlueHighlightColor))
    
    def unhighlight_root(self):
        self.block_list[0].set_auto_highlight(HighlightColor(HighlightStandardColor.NoHighlightColor))
        

    def _add_dropdown(self, items:list):
        combo = QComboBox()
        combo.addItems(items)

        combo.currentIndexChanged.connect(lambda idx, c=combo: self._on_dropdown_changed(c, idx))
        combo.highlighted.connect(lambda idx, c=combo: self._temp_block_highlight(c, idx))
        self.content_layout.addWidget(combo)
        self.dropdowns.append(combo)
        
    def _temp_block_highlight(self, combo:QComboBox, index:int):
        if self.last_temp_highlight is not None:
            self.last_temp_highlight.set_auto_highlight(HighlightColor(HighlightStandardColor.NoHighlightColor))
            if self.last_temp_highlight in self.block_list:
                self.highlight_root()
                self.last_temp_highlight.set_auto_highlight(HighlightColor(HighlightStandardColor.BlueHighlightColor))
            self.last_temp_highlight = None
        if index != 0:
            drop_index = self.dropdowns.index(combo)
            sel_block = self.block_list[drop_index].outgoing_edges[index-1].target
            self.highlight_root()
            sel_block.set_auto_highlight(HighlightColor(HighlightStandardColor.YellowHighlightColor))
            self.last_temp_highlight = sel_block    
            
    def _add_block(self, combo:QComboBox):
        new_block = None
        last_block_index = len(self.block_list) - 1
        for edge in self.block_list[last_block_index].outgoing_edges:
            if int(combo.currentText(), 16) == edge.target[0].address:
                new_block = edge.target
        if new_block is not None:
            self.block_list.append(new_block)
            drop_items = ["Select an Option..."]
            drop_items.extend([f"0x{path.target[0].address:x}" for path in new_block.outgoing_edges])
            if len(drop_items) == 1:
                drop_items = ["No Outgoing Edges"]
            self.last_temp_highlight.set_auto_highlight(HighlightColor(HighlightStandardColor.NoHighlightColor))
            self.last_temp_highlight = None
            if last_block_index == 0:
                self.highlight_root()
            new_block.set_auto_highlight(HighlightColor(HighlightStandardColor.BlueHighlightColor))
            
            self._add_dropdown(drop_items)

    def _on_dropdown_changed(self, combo:QComboBox, index:int):
        end = len(self.dropdowns)
        c_index = self.dropdowns.index(combo)
        if c_index < end - 1:
            self._remove_dropdowns((end - 1) - c_index)
            if index == 0:
                pass
            else:
                self._add_block(combo)
        else:
            self._add_block(combo)
        
        
class OldCFPTab(QComboBox):
    """The SSA Variable Tab for the bANGR plugin.

    Args:
        QTableWidget (QTableWidget): The inherited QTableWidget from Binary Ninja
    """

    def __init__(self, bv:BinaryView):
        super().__init__()
        text="Select an option..."

        self.bv = bv
        self.setPlaceholderText(text)

        self.setMinimumWidth(0)
        self.setMaximumHeight(50)

        self.currentIndexChanged.connect(self._on_selection_changed)

    def updateContext(self, current_offset:int):
        
        func = next(iter(self.bv.get_functions_containing(current_offset)), None)
        if func is None: return
        func = func.mlil_if_available
        if not func: return
        
        pathgen = CFGPathExtractor(func)
        test = pathgen.get_paths()
        path_ints = pathgen.get_path_ints()
        path_strs = [str(path) for path in path_ints]
        self.clear()
        self.addItems(path_strs)



    def _on_selection_changed(self, index):

        print(f"[BNComboBox] Selected: {self.itemText(index)}")

    def get_selected_value(self):
        return self.currentText()
            
