#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "Qt6::qwaylandcompositorplugin" for configuration "Release"
set_property(TARGET Qt6::qwaylandcompositorplugin APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Qt6::qwaylandcompositorplugin PROPERTIES
  IMPORTED_COMMON_LANGUAGE_RUNTIME_RELEASE ""
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/./qml/QtWayland/Compositor/libqwaylandcompositorplugin.so"
  IMPORTED_NO_SONAME_RELEASE "TRUE"
  )

list(APPEND _cmake_import_check_targets Qt6::qwaylandcompositorplugin )
list(APPEND _cmake_import_check_files_for_Qt6::qwaylandcompositorplugin "${_IMPORT_PREFIX}/./qml/QtWayland/Compositor/libqwaylandcompositorplugin.so" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
