#  B2-X Time Optimizer

A lightweight program which monitors packets and runs scripts if certain ports are idle, then again when they stop being idle. This allows to e.g. stop an app when it isn't receiving packets, then start it when it does.

*Control, control, you must learn control!*

## Scope
- Monitors TCP and UDP port activity (stores latest timestamps).
- Provides a JSON configuration file to specify what ports to monitor, what scripts to run, and what the idle time is.
- Can run `start` and `stop` bash commands. `stop` is run when all ports of an app have not received packets for a configured amount of time (`idle` time). `start` is run when a stopped app receives a packet on one of it's ports.

## Install
- You need `zig` to compile the project. At runtime you'll need `libpcap`.

1. Follow steps to install `libpcap` first.
1. `git clone git@github.com:tomasz-lisowski/b2xto.git`
2. `cd b2xto`
3. `zig build -Doptimize=ReleaseSafe`

### Install `libpcap`
1. `git clone git@github.com:the-tcpdump-group/libpcap.git`
2. `cd libpcap`
3. `./configure` (this might require extra dependencies to work, but it will indicate what is missing).
4. `make`
5. `sudo make install`

## Usage
1. Create a JSON config file like `example/config.json`.
2. Find out the name of the network interface that will be monitored. It will be one of `ip link show`.
3. `./zig-out/bin/b2xto eth0 ./config.json`
