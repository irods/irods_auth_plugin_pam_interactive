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

## Configuration

### Server-side configuration

#### Require TLS/SSL

It is **highly recommended** that TLS/SSL be required in the server when using this plugin for authentication. More information about configuring iRODS to use TLS/SSL can be found here: [https://docs.irods.org/4.3.2/plugins/pluggable_authentication/#server-ssl-setup](https://docs.irods.org/4.3.2/plugins/pluggable_authentication/#server-ssl-setup)

#### `R_GRID_CONFIGURATION` for TTL

This plugin uses the standard set of authentication configurations found in `R_GRID_CONFIGURATION` for configuring Time-To-Live (TTL) on authenticated "sessions". You can read about these configurations here: [https://docs.irods.org/4.3.2/system_overview/configuration/#authentication-configuration](https://docs.irods.org/4.3.2/system_overview/configuration/#authentication-configuration)

#### `server_config.json` configuration: `insecure_mode`

`insecure_mode` gives the iRODS administrator the ability to allow for non-TLS/SSL-enabled communications between the client and the server for authentications using `pam_interactive`. TLS/SSL is required by default when using this plugin because sensitive user information is sent over the network to communicate with the PAM service via the catalog service provider. **It is highly recommended to leave this configuration option at its default value of `false`.** The configuration option has been introduced for demo and testing purposes.

If the value is set to `true` and the user attempting to authenticate using this plugin does not have TLS/SSL enabled in the client-server communications, it is allowed, and a warning message is written to the server log to remind the administrator that sensitive user information is being sent over the network without encryption. If the value is set to `false`, a `SYS_NOT_ALLOWED` error will be returned if the user attempting to authenticate using this plugin does not have TLS/SSL enabled in the client-server communications. In the absence of this configuration, a default value of `false` is used.

Here is how to configure `insecure_mode`:
```javascript
"plugin_configuration": {
    "authentication": {
        "pam_interactive": {
            "insecure_mode": false
        }
    }
}
```

#### Logging

The server-side plugin includes a logging category which can be configured in `server_config.json` under the `log_level` section like so:
```javascript
"log_level": {
    // ... Other Log Categories ...

    "pam_interactive_auth_plugin": "info",

    // ... Other Log Categories ...
},
```

### Client-side configuration

Set the `irods_authentication_scheme` in the client environment to `pam_interactive`.

The client environment should be configured to use TLS/SSL if the server requires TLS/SSL. More information about configuring the iRODS client environment to use TLS/SSL can be found here: [https://docs.irods.org/4.3.2/plugins/pluggable_authentication/#client-ssl-setup](https://docs.irods.org/4.3.2/plugins/pluggable_authentication/#client-ssl-setup)

## Example Implementations and Usage

### Linux password authentication (i.e. `pam_password`)

This plugin can be used as a drop-in replacement for `pam_password` and the legacy PAM authentication plugin (with the exception of some differing prompts). Here's how to set it up.

#### Setting up users

In order to use the plugin in this case, a PAM user with a password must exist and be permitted to authenticate in the Linux environment with a password. There must also exist an iRODS user in the local zone with the same name as the PAM user. For example, if there is a PAM user named `alice` to whom we want to give iRODS access, an iRODS user named `alice` must also exist in the zone with which the user will be authenticating.

Here is a simple way to create a Linux user with a password (note: this requires root access):
```bash
sudo useradd -m alice # the -m means "create a home directory"
sudo usermod -p password_for_alice alice
```

Here is a simple way to create an iRODS user (note: this requires `rodsadmin` permissions):
```bash
iadmin mkuser alice rodsuser
```

#### Configure the PAM stack

Configure the `irods` PAM stack as described in the documentation for PAM authentication (see [https://docs.irods.org/4.3.2/plugins/pluggable_authentication/#pam-pluggable-authentication-module](https://docs.irods.org/4.3.2/plugins/pluggable_authentication/#pam-pluggable-authentication-module)):
```
$ cat /etc/pam.d/irods
auth        required      pam_env.so
auth        sufficient    pam_unix.so
auth        requisite     pam_succeed_if.so uid >= 500 quiet
auth        required      pam_deny.so
```

#### Try it out

Switch to the Linux user that we wish to authenticate. The user should be able to run `iinit` and see the following:
```bash
$ iinit
Enter your iRODS user name: alice
Password: 
```

If "Password" is entered correctly, the user will be authenticated with iRODS, just like `pam_password`. The "Password" prompt is coming from the `pam_unix` module. For more information about this module, see the documentation in **man pam_unix**, or [https://linux.die.net/man/8/pam_unix](https://linux.die.net/man/8/pam_unix).

### Kerberos authentication

This plugin can be used as a replacement for the Kerberos authentication plugin ([https://github.com/irods/irods_auth_plugin_kerberos](https://github.com/irods/irods_auth_plugin_kerberos)). Here's how to set it up.

#### Set up the Kerberos service

Make sure that your organization has a Kerberos service. For information about how to do this, please see the official Kerberos documentation: [http://web.mit.edu/kerberos/krb5-current/doc/admin/install.html](http://web.mit.edu/kerberos/krb5-current/doc/admin/install.html) In the "Additional References", the Kerberos team has provided an externally written guide for installing and configuring Kerberos on Debian-based systems which may prove helpful: [http://techpubs.spinlocksolutions.com/dklar/kerberos.html#intro](http://techpubs.spinlocksolutions.com/dklar/kerberos.html#intro)

#### Setting up users

In order to use the plugin in this case, a Kerberos user with a password must exist and be permitted to authenticate in the Kerberos environment with a password. There must also exist an iRODS user in the local zone with the same name as the Kerberos user. For example, if there is a Kerberos user named `alice` to whom we want to give iRODS access, an iRODS user named `alice` must also exist in the zone with which the user will be authenticating.

Here is a simple way to create a user in Kerberos (note: requires admin privileges in Kerberos). First, run `kadmin` and authenticate as the Kerberos administrator (if you are connected directly to a Kerberos administration server, you can use `kadmin.local`). Then, you can run this to create an unprivileged user:
```bash
addprinc -policy user alice
```

Here is a simple way to create an iRODS user (note: this requires `rodsadmin` permissions):
```bash
iadmin mkuser alice rodsuser
```

#### Configure the PAM stack

In order to use Kerberos via PAM, we need to install the Kerberos PAM module, `pam_krb5`. Locating this software package is an exercise left to the reader. If all else fails, the .tar.gz files and source code can be found here: [https://www.eyrie.org/~eagle/software/pam-krb5](https://www.eyrie.org/~eagle/software/pam-krb5)

For more information about this module, see the documentation in **man pam_krb5**, or [https://linux.die.net/man/8/pam_krb5](https://linux.die.net/man/8/pam_krb5).

Configure the `irods` PAM stack as described in the documentation for PAM authentication (see [https://docs.irods.org/4.3.2/plugins/pluggable_authentication/#pam-pluggable-authentication-module](https://docs.irods.org/4.3.2/plugins/pluggable_authentication/#pam-pluggable-authentication-module)):
```
$ cat /etc/pam.d/irods
auth    sufficient    pam_krb5.so minimum_uid=1000
auth    requisite     pam_deny.so
auth    required      pam_permit.so
```
Note: The PAM stack doesn't have to look exactly like this. For instance, Linux authentication via `pam_unix` can be used as a backup if Linux users exist and are allowed to authenticate with a password in your system. This example is just demonstrating Kerberos authentication for iRODS via PAM in a very simple manner.

#### Try it out

Switch to the PAM user that we wish to authenticate. The user should be able to run `iinit` and see the following:
```bash
$ iinit
Enter your iRODS user name: alice
Password: 
```

If "Password" is entered correctly, the user will be authenticated with iRODS. The "Password" prompt is coming from the `pam_krb5` module.

## Testing

Running the tests for this plugin should be familiar to those who have run tests for other iRODS plugins. This repository provides a test hook which is used by the iRODS Testing Environment. You can read about how to run plugin tests in the testing environment here: [https://github.com/irods/irods_testing_environment/?tab=readme-ov-file#run-irods-plugin-tests](https://github.com/irods/irods_testing_environment/?tab=readme-ov-file#run-irods-plugin-tests) Please note that using the `--use-ssl` option with the testing environment could cause tests to be skipped, so, as usual, please be mindful of which options are being used when running tests.

In order to run tests aside from the tools provided by the testing environment, one can use the `run_tests.py` script provided by the iRODS server package:
```bash
python3 scripts/run_tests.py --run_specific_test test_irods_auth_plugin_pam_interactive
```

Use the `--help` option for `run_tests.py` to learn about other options. Please note that the test files are installed with the server package produced by this repository so it is assumed that a packaged installation is being used. If not, make sure that the test files in the `packaging` directory are placed alongside the other iRODS test files (for default packaged installations, this should be `/var/lib/irods/scripts/irods/test`).
