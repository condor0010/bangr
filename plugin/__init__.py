from binaryninjaui import Sidebar, SidebarWidgetType, SidebarWidgetLocation
from .settings import BangrSettings
from .ui.sidebar_widget import VariableListWidgetType

def register_sidebar_widget():
    Sidebar.addSidebarWidgetType(VariableListWidgetType())

register_sidebar_widget()
BangrSettings()

