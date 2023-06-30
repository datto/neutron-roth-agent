# Change Log

All notable changes will be documented in this file.

## [0.0.5] - 2023-06-30

### [0.0.5] Added

### [0.0.5] Changed

### [0.0.5] Fixed

- The drop-in unit file for frr is now written to 10-neutron_roth_agent.conf instead
  of override.conf. This fixes an issue where system administrators may have their
  own override.conf file installed for frr, and the files would step on each other.
- _neighbor_manager now runs up to 30 parallel threads. This fixes an issue where
  having many ARP entries on a node would take the agent longer than the default
  60s to run.
- Fixed some cosmetic markdown lint problems in the README and PKG-INFO files.

## [0.0.4] - 2023-06-14

### [0.0.4] Added

### [0.0.4] Changed

- frr related files are now written to /var/lib/neutron/roth instead of /etc/neutron.

### [0.0.4] Fixed

## [0.0.3] - 2022-06-20

### [0.0.3] Added

- [parseconfig.py](/src/neutron_roth_agent/parseconfig.py)
- [roth_agent.ini](/src/neutron_roth_agent/data/roth_agent.ini)
  Configuration variables have been moved to `/etc/neutron/roth_agent.ini`
- Neutron router frr support
  The agent now supports adding frr namespace instances to neutron routers
  to dynamically advertise connected routes via the provider interface.
  Only prefixes in the same shared address scope as the provider prefix are considered.
  Prefixes must be members of subnet pools.

### [0.0.3] Changed

### [0.0.3] Fixed

- Fixed a bug in orphan manager where instances of no matching interface types
  would throw an error.
