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

## Usage

SSL is required to be configured for both the server and the client, even if the iRODS server does not require its use. More information about configuring iRODS to use SSL can be found here: [https://docs.irods.org/4.3.2/plugins/pluggable_authentication/#server-ssl-setup](https://docs.irods.org/4.3.2/plugins/pluggable_authentication/#server-ssl-setup)

Set the `irods_authentication_scheme` in the client environment to `pam_interactive`.

### Example implementation: Replacement for `pam_password` authentication

This plugin can be used as a drop-in replacement for `pam_password` (with the exception of some differing prompts). Here's how to set it up.

Configure the `irods` PAM stack as described in the documentation for PAM authentication (see [https://docs.irods.org/4.3.2/plugins/pluggable_authentication/#pam-pluggable-authentication-module](https://docs.irods.org/4.3.2/plugins/pluggable_authentication/#pam-pluggable-authentication-module)):
```
$ cat /etc/pam.d/irods
auth        required      pam_env.so
auth        sufficient    pam_unix.so
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        required      pam_deny.so
```

The user should then be able to run `iinit` and see the following:
```bash
$ iinit
Enter your iRODS user name: alice
Password: 
```

If "Password" is entered correctly, the user will be authenticated with iRODS, just like `pam_password`. The "Password" prompt is coming from the `pam_unix` module. For more information about this module, see the documentation in **man pam_unix**, or [https://linux.die.net/man/8/pam_unix](https://linux.die.net/man/8/pam_unix).
