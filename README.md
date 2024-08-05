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

## Configuration

This plugin uses the standard set of authentication configurations found in `R_GRID_CONFIGURATION`. You can read about these configurations here: [https://docs.irods.org/4.3.2/system_overview/configuration/#authentication-configuration](https://docs.irods.org/4.3.2/system_overview/configuration/#authentication-configuration)

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

## Logging

The server-side plugin includes a logging category which can be configured in `server_config.json` under the `log_level` section like so:
```javascript
"log_level": {
    // ... Other Log Categories ...

    "pam_interactive_auth_plugin": "info",

    // ... Other Log Categories ...
},
```

## Testing

Running the tests for this plugin should be familiar to those who have run tests for other iRODS plugins. This repository provides a test hook which is used by the iRODS Testing Environment. You can read about how to run plugin tests in the testing environment here: [https://github.com/irods/irods_testing_environment/?tab=readme-ov-file#run-irods-plugin-tests](https://github.com/irods/irods_testing_environment/?tab=readme-ov-file#run-irods-plugin-tests) Please note that using the `--use-ssl` option with the testing environment could cause tests to be skipped, so, as usual, please be mindful of which options are being used when running tests.

In order to run tests aside from the tools provided by the testing environment, one can use the `run_tests.py` script provided by the iRODS server package:
```bash
python3 scripts/run_tests.py --run_specific_test test_irods_auth_plugin_pam_interactive
```

Use the `--help` option for `run_tests.py` to learn about other options. Please note that the test files are installed with the server package produced by this repository so it is assumed that a packaged installation is being used. If not, make sure that the test files in the `packaging` directory are placed alongside the other iRODS test files (for default packaged installations, this should be `/var/lib/irods/scripts/irods/test`).
