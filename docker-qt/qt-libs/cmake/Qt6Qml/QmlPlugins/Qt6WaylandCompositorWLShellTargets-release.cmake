#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "Qt6::WaylandCompositorWLShell" for configuration "Release"
set_property(TARGET Qt6::WaylandCompositorWLShell APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Qt6::WaylandCompositorWLShell PROPERTIES
  IMPORTED_COMMON_LANGUAGE_RUNTIME_RELEASE ""
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/./qml/QtWayland/Compositor/WlShell/libwaylandcompositorwlshellplugin.so"
  IMPORTED_NO_SONAME_RELEASE "TRUE"
  )

list(APPEND _cmake_import_check_targets Qt6::WaylandCompositorWLShell )
list(APPEND _cmake_import_check_files_for_Qt6::WaylandCompositorWLShell "${_IMPORT_PREFIX}/./qml/QtWayland/Compositor/WlShell/libwaylandcompositorwlshellplugin.so" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
