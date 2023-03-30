# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---
## [0.2.10] - 2023-03-20

### Added

- Added option to disable ssh support on a per interface basis

### Fixed

- added additional check in tproxy_splicer_startup.sh to verify if icmp-echo is already enabled in UFW to avoid cases where errors are are causing ziti-router to reload do not result in UFW reloading
  when icmp.enable == true in the user_ingress_rules.yml.

## [0.2.9] - 2023-03-20

### Fixed

- fixed etables insert performance issue when inserting large numbers of services. 

## [0.2.8] - 2023-03-20

### Added

- added -v, --verbose <ifname> option to enable and disable trace output.  -d --disable when added disables verbose mode.  default is disabled.

### Changed

- Updated the logic for the local fw rules in the lifecycle script; included source address in all rules as configured by the ufw firewall.

## [0.2.7] - 2023-03-15

### Fixed

- Updated the router service file with the single binary router run command
- Updated the ufw rule deletion logic, when diverter-disable is invoked

## [0.2.6] - 2023-03-13

### Added

- Added support for source address filtering
- Added rule to permananetly allow icmp echo replies from any source
- Added command line switch to etables to allow icmp echos into router
- Added check for maximum prefix tuples reached and current usage in etables -L

## [0.2.5] - 2023-02-21

### Bug Fix

- Added check for maximum port ranges reached for a particular prefix destination

## [0.2.4] - 2023-02-16

### Bug Fix

- Fixed typo in output when invalid IP address entered

## [0.2.3] - 2023-02-13

### Bug fix

- Fixed issue where if an interface exists that has an UNSPEC address family caused etables binary to segment fault.


## [0.2.2] - 2023-02-10

### Added

- 2 options to tproxy startup script
    - `--add-user-ingress-rules`        true if adding user ingress rules to ebpf map (based on yaml formatted content of ebpf_user_file=$EBPF_HOME/user_ingress_rules.yml)
    - `--delete-user-ingress-rules`     true if deleting user ingress rules from ebpf map (based on yaml formatted content of ebpf_user_file=$EBPF_HOME/user_ingress_rules.yml)

### Changed

- `--check-ebpf-status`  - now it indicates if the ebpf program is attached and shows the interface name in addtion to the trace raw command details.

---

## [0.2.1] - 2023-02-03

### Changed

- change map_update to etables

### Added 

- 2 options to etables program to further filter option -L --list
    - `-f, --passthrough`    list passthrough rules <optional list>
    - `-i, --intercepts`     list intercept rules <optional for list>

---

## [0.2.0] - 2023-01-31

### Changed

- diverter object file is now compiled with 3 different map size options
    - small  = 1000  entries
    - medium = 5000  entries
    - large  = 10000 entries

---

## [0.1.0] - 2023-01-30

### Added 

- Initial Version
