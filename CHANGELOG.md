# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.6] - 2023-02-21

- Added support for source address filtering
- Added rule to permananetly allow icmp echo replies from any source
- Added command line switch to etables to allow icmp echos into router

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

