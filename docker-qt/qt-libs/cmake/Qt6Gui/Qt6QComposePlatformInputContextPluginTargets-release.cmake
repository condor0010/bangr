#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "Qt6::QComposePlatformInputContextPlugin" for configuration "Release"
set_property(TARGET Qt6::QComposePlatformInputContextPlugin APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Qt6::QComposePlatformInputContextPlugin PROPERTIES
  IMPORTED_COMMON_LANGUAGE_RUNTIME_RELEASE ""
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/./plugins/platforminputcontexts/libcomposeplatforminputcontextplugin.so"
  IMPORTED_NO_SONAME_RELEASE "TRUE"
  )

list(APPEND _cmake_import_check_targets Qt6::QComposePlatformInputContextPlugin )
list(APPEND _cmake_import_check_files_for_Qt6::QComposePlatformInputContextPlugin "${_IMPORT_PREFIX}/./plugins/platforminputcontexts/libcomposeplatforminputcontextplugin.so" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)