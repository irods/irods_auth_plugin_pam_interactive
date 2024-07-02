# irods_auth_plugin_pam_interactive

## How to build

The following packages are required to build this project:
 - irods-dev
 - irods-runtime

You will also need CMake of minimum version 3.12.0 and Clang of minimum version 13.0.0. These can be acquired through the following iRODS externals packages:
 - irods-externals-cmake3.21.4-0
 - irods-externals-clang13.0.0-0

To build, run the following:
```bash
mkdir -p build && cd build
cmake ..
make package
```

## How to build with Docker

This project uses a "build hook" which allows the [iRODS Development Environment](https://github.com/irods/irods_development_environment) to build packages in the usual manner. Please see the instructions for building plugins with the development environment: [https://github.com/irods/irods_development_environment?tab=readme-ov-file#how-to-build-an-irods-plugin](https://github.com/irods/irods_development_environment?tab=readme-ov-file#how-to-build-an-irods-plugin)
