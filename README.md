# snmp-traffic-control

Export Linux qdisc stats via net-snmp.

## Usage

This program should be used by net-snmp under the pass_persist directive:

```net-snmp
pass_persist .1.3.6.1.3.2020 /config/user-data/snmp-traffic-control
```

## Building

Building develement:

```sh
cargo build
```

Build for Octeon (Ubiquiti Edgerouter):

```sh
cargo +nightly build --release --target mips64-unknown-linux-muslabi64
```

Note: nightly (1.48.0) is required right now because stable (1.47.0) does not work.
