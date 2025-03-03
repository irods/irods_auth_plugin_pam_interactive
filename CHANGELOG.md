# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project **only** adheres to the following _(as defined at [Semantic Versioning](https://semver.org/spec/v2.0.0.html))_:

> Given a version number MAJOR.MINOR.PATCH, increment the:
> 
> - MAJOR version when you make incompatible API changes
> - MINOR version when you add functionality in a backward compatible manner
> - PATCH version when you make backward compatible bug fixes

## [0.1.1] - 2025-03-XX

This release addresses issues with packaging and availability. There are no functional changes to the plugin's implementation.

### Changed

- Make RPM packages accessible via packages.irods.org (#55).

### Fixed

- Include postinst script in server package only (#56).

## [0.1.0] - 2024-08-26

This is the first release of the PAM Interactive authentication plugin.

It enables organizations to develop dynamic authentication flows that meet their needs.
