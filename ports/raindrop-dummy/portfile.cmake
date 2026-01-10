vcpkg_from_github(
  OUT_SOURCE_PATH SOURCE_PATH
  REPO Rainfall-Studio/Raindrop-Dummy
  REF v0.1.0
  SHA512 0
)

vcpkg_cmake_configure(SOURCE_PATH "${SOURCE_PATH}")
vcpkg_cmake_install()

vcpkg_cmake_config_fixup(
  PACKAGE_NAME RaindropDummy
  CONFIG_PATH lib/cmake/RaindropDummy
)

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
