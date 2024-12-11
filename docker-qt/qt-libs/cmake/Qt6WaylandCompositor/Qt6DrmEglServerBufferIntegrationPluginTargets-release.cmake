#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "Qt6::DrmEglServerBufferIntegrationPlugin" for configuration "Release"
set_property(TARGET Qt6::DrmEglServerBufferIntegrationPlugin APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(Qt6::DrmEglServerBufferIntegrationPlugin PROPERTIES
  IMPORTED_COMMON_LANGUAGE_RUNTIME_RELEASE ""
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/./plugins/wayland-graphics-integration-server/libqt-wayland-compositor-drm-egl-server-buffer.so"
  IMPORTED_NO_SONAME_RELEASE "TRUE"
  )

list(APPEND _cmake_import_check_targets Qt6::DrmEglServerBufferIntegrationPlugin )
list(APPEND _cmake_import_check_files_for_Qt6::DrmEglServerBufferIntegrationPlugin "${_IMPORT_PREFIX}/./plugins/wayland-graphics-integration-server/libqt-wayland-compositor-drm-egl-server-buffer.so" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
