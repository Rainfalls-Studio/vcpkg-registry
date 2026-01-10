vcpkg_from_github(
  OUT_SOURCE_PATH SOURCE_PATH
  REPO Rainfalls-Studio/Dummy
  REF v0.1.1
  SHA512 c98e6a65df88f0d87b2c551ce9b9be92220547ceda4e3e076f81bd4d72fcc0936b59b74149b3b7327eacafe376eb80cb6460af1b00f9884d25b1a3d12f892845
)

vcpkg_cmake_configure(SOURCE_PATH "${SOURCE_PATH}")
vcpkg_cmake_install()

vcpkg_cmake_config_fixup(
  PACKAGE_NAME RaindropDummy
  CONFIG_PATH lib/cmake/RaindropDummy
)
