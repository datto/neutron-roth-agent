# Change Log

All notable changes will be documented in this file.

## [0.0.3] - 2022-06-20

### Added

- [parseconfig.py](/src/neutron_roth_agent/parseconfig.py)
- [roth_agent.ini](/src/neutron_roth_agent/data/roth_agent.ini)
  Configuration variables have been moved to `/etc/neutron/roth_agent.ini`
- Neutron router frr support
  The agent now supports adding frr namespace instances to neutron routers
  to dynamically advertise connected routes via the provider interface.
  Only prefixes in the same shared address scope as the provider prefix are considered.
  Prefixes must be members of subnet pools.

### Changed

### Fixed

- Fixed a bug in orphan manager where instances of no matching interface types
  would throw an error.
