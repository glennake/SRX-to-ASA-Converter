# SRX to ASA Converter

Juniper SRX to Cisco ASA Configuration Converter Tool v1.1 by Eugene Khabarov<br>
This is fork of SRX-to-ASA-Converter by Glenn Akester, original thanks should be addressed to him

## Requirements

- Python 2.7

## Dependencies

- netaddr

## Usage

python convert.py /full/path/to/config

## Changes in version 1.1

- Objects and object-groups parsing is fixed
- Port ranges are handled correctly now
- Converter creates ASA security zones for each SRX security zone and assign uniq nameif for each ASA interface
- VLAN (ASA subinterfaces) are created now
- Security level for trusted or inside is 100 by default now, for outside and external is 0 by default
- More static applications were defined
- Few other fixes

## Changes in version 1.2

- Support for global address/address-sets

## Changes in version 1.3

- Additional static applications added
- Support for dns name address objects
- Support for any-ipv4 and any-ipv6 default addresses

## Changes in version 1.4

- Object name pattern moved to global variable
- Support for "." in object names
- Typo's
- Code formatting
