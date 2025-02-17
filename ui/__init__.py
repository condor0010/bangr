from binaryninjaui import Sidebar, SidebarWidgetType, SidebarWidgetLocation
from .variable_list import VariableListWidgetType

def register_sidebar_widget():
    Sidebar.addSidebarWidgetType(VariableListWidgetType())

register_sidebar_widget()

