vcpkg_from_github(
  OUT_SOURCE_PATH SOURCE_PATH
  REPO Rainfalls-Studio/RaindropCore
  REF v0.1.0
  SHA512 0314e69823050d43ddaf47b0fb6a6acf88dd993fc27ea88dafcb4af64e23459727981e83caad75575fd35ce7301d831ed7e6ddd9d8a373fd108247d2ec1d62f3
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DRAINDROP_BUILD_TESTS=OFF
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(
  PACKAGE_NAME RaindropCore
  CONFIG_PATH lib/cmake/RaindropCore
)
