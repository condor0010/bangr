#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "Qt6::QuickControls2Imagine" for configuration "Release"
set_property(TARGET Qt6::QuickControls2Imagine APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Qt6::QuickControls2Imagine PROPERTIES
  IMPORTED_LINK_DEPENDENT_LIBRARIES_RELEASE "Qt6::QuickControls2ImagineStyleImpl;Qt6::Qml;Qt6::Core"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libQt6QuickControls2Imagine.so.6.7.2"
  IMPORTED_SONAME_RELEASE "libQt6QuickControls2Imagine.so.6"
  )

list(APPEND _cmake_import_check_targets Qt6::QuickControls2Imagine )
list(APPEND _cmake_import_check_files_for_Qt6::QuickControls2Imagine "${_IMPORT_PREFIX}/lib/libQt6QuickControls2Imagine.so.6.7.2" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
