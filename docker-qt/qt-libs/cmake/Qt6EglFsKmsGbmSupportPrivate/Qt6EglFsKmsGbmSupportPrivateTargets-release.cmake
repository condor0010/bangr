#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "Qt6::EglFsKmsGbmSupportPrivate" for configuration "Release"
set_property(TARGET Qt6::EglFsKmsGbmSupportPrivate APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Qt6::EglFsKmsGbmSupportPrivate PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libQt6EglFsKmsGbmSupport.so.6.7.2"
  IMPORTED_SONAME_RELEASE "libQt6EglFsKmsGbmSupport.so.6"
  )

list(APPEND _cmake_import_check_targets Qt6::EglFsKmsGbmSupportPrivate )
list(APPEND _cmake_import_check_files_for_Qt6::EglFsKmsGbmSupportPrivate "${_IMPORT_PREFIX}/lib/libQt6EglFsKmsGbmSupport.so.6.7.2" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
