#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "Qt6::QWaylandWlShellIntegrationPlugin" for configuration "Release"
set_property(TARGET Qt6::QWaylandWlShellIntegrationPlugin APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Qt6::QWaylandWlShellIntegrationPlugin PROPERTIES
  IMPORTED_COMMON_LANGUAGE_RUNTIME_RELEASE ""
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/./plugins/wayland-shell-integration/libwl-shell-plugin.so"
  IMPORTED_NO_SONAME_RELEASE "TRUE"
  )

list(APPEND _cmake_import_check_targets Qt6::QWaylandWlShellIntegrationPlugin )
list(APPEND _cmake_import_check_files_for_Qt6::QWaylandWlShellIntegrationPlugin "${_IMPORT_PREFIX}/./plugins/wayland-shell-integration/libwl-shell-plugin.so" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
