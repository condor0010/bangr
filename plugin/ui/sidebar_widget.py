# sidebar_widget.py
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
from functools import partial
from .tabs import SSAVarTab, VarTab, CFPTab

class VariableListWidget(SidebarWidget):
    def __init__(self, name, frame, bv: BinaryView):
        super().__init__(name)
        self.bv, self.current_offset = bv, 0
        self.previous_highlighted = []
        self._setup_ui()
        self._populate_variable_list()
    
    def _setup_ui(self):

        layout = QVBoxLayout(self)

        self.search_bar = QLineEdit(placeholderText="Search Variables...")
        self.search_bar.textChanged.connect(self.filter_tabs)

        layout.addWidget(self.search_bar)
        
        self.tabWidget = QTabWidget()

        self.VarTab = VarTab(self.bv, self.current_offset)
        self.SSAVarTab = SSAVarTab(self.bv, self.current_offset)
        self.CFPTab = CFPTab(self.bv, self.current_offset)

        for tab, name in [
            (self.VarTab, "Variables"),
            (self.SSAVarTab, "SSA Variables"),
            (self.CFPTab, "Control Flow Path")
        ]: self.tabWidget.addTab(tab, name)

        layout.addWidget(self.tabWidget)
        self._populate_variable_list()

        self.VarTab.itemSelectionChanged.connect(lambda: self.highlight_instructions(self.VarTab.selectedItems()))
        self.SSAVarTab.itemSelectionChanged.connect(lambda: self.ssa_highlight_instructions(self.SSAVarTab.selectedItems()))

    def ssa_highlight_instructions(self, selected_items):
        if not selected_items or not self.bv:
            return

        try:
            name, version = selected_items[0].text().split("#")
            selected_var_text_str = f"<SSAVariable: {name} version {version}>"
        except ValueError:
            print(f"Invalid SSA variable format: {selected_items[0].text()}")
            return

        func = next(iter(self.bv.get_functions_containing(self.current_offset)), None)
        if not func:
            return

        list(
            map(
            partial(
                func.set_user_instr_highlight,
                color=HighlightStandardColor.NoHighlightColor),
            self.previous_highlighted
            ))

        self.previous_highlighted.clear()

        mlil_ssa_func = func.mlil.ssa_form
        matching_var = None

        for ssa_var in mlil_ssa_func.ssa_vars:
            if selected_var_text_str == str(ssa_var):
                matching_var = ssa_var
                break

        if not matching_var:
            print(f"No matching MLIL SSA variable found for: {selected_var_text_str}")
            return

        for ssa_instr in mlil_ssa_func.instructions:
            if matching_var in ssa_instr.vars_read or matching_var in ssa_instr.vars_written:
                addr = ssa_instr.address
                func.set_user_instr_highlight(addr, HighlightStandardColor.BlueHighlightColor)
                self.previous_highlighted.append(addr)

    def highlight_instructions(self, selected_items):
        if not selected_items or not self.bv: return

        selected_var = selected_items[0].text()
        func = next(iter(self.bv.get_functions_containing(self.current_offset)), None)
        if not func: return

        list(
            map(
            partial(
                func.set_user_instr_highlight,
                color=HighlightStandardColor.NoHighlightColor),
            self.previous_highlighted
            ))
        self.previous_highlighted.clear()

        for block in func.basic_blocks:
            for instr in block.get_disassembly_text():
                if any(selected_var in token.text for token in instr.tokens):
                    func.set_user_instr_highlight(instr.address, HighlightStandardColor.BlueHighlightColor)
                    self.previous_highlighted.append(instr.address)

    def _populate_variable_list(self):
        self.VarTab.populate_variables(self.current_offset)
        self.SSAVarTab.populate_variables(self.current_offset)
        self.CFPTab.updateContext(self.current_offset)
        
    def notifyViewLocationChanged(self, view, location):
        if location: self.current_offset = location.getOffset()
        self._populate_variable_list()
        func = next(iter(self.bv.get_functions_containing(self.current_offset)), None)
        if func is None: return
        list(
            map(
            partial(
                func.set_user_instr_highlight,
                color=HighlightStandardColor.NoHighlightColor),
            self.previous_highlighted
            ))
        self.previous_highlighted.clear()

    def notifyVariableRenamed(self, var, name):
        self._populate_variable_list()
    
    def function_updated(self, view, func):
        self._populate_variable_list()

    def filter_tabs(self):
        self.filter_variables(self.search_bar, self.VarTab)
        self.filter_variables(self.search_bar, self.SSAVarTab)

    def filter_variables(search_bar, variable_table: QTableWidget):
        search_text = search_bar.text().lower()
        for row in range(variable_table.rowCount()):
            variable_table.setRowHidden(row, search_text not in variable_table.item(row, 0).text().lower())
                    
class VariableListWidgetType(SidebarWidgetType):
    name = "bANGR Panel"
    
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

