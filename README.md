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

You can also build packages by running the `plugin_builder` Docker Image. The container runs a script which follows the instructions above for building. The source code and build directory are provided to the container via volume mounts at run time so that the build artifacts and packages will be stored on the host machine.

To get started, build the builder image, e.g.:
```
docker build -f plugin_builder.ubuntu20.Dockerfile -t pam-interactive-builder:ubuntu-20.04 .
```

Then, run the builder, e.g.:
```
docker run -it --rm \
    -v /path/to/fork/of/irods_auth_plugin_pam_interactive:/src:ro \
    -v /path/to/fork/of/irods_auth_plugin_pam_interactive/build:/bld \
    pam-interactive-builder:ubuntu-20.04
```

The package builder image supports building with custom iRODS packages if the plugin is being built/tested with unreleased code. The `--irods-packages` option was created for this purpose and will install the locally built packages at the specified path, when used. The option must specify a directory inside the container which contains the required packages to build the plugin appropriate to the target platform. This can be accomplished through a read-only volume mount. The directory mountpoint is then used with the option and can be named whatever you want, as long as it matches the volume mount specification. Here is an example usage (target platform is ubuntu-20.04):
```bash
$ ls /path/to/built/packages
irods-dev_4.3.0-1~focal_amd64.deb  irods-runtime_4.3.0-1~focal_amd64.deb  <...>
$ docker run -it --rm \
    -v /path/to/fork/of/irods_auth_plugin_pam_interactive:/src:ro \
    -v /path/to/fork/of/irods_auth_plugin_pam_interactive/build:/bld \
    -v /path/to/built/packages:/my_irods_packages:ro \
    pam-interactive-builder:ubuntu-20.04 --irods-packages /my_irods_packages
```
