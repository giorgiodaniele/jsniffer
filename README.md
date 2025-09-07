# Java Packet Sniffer

A lightweight network packet sniffer written in Java using [pcap4j](https://github.com/kaitoy/pcap4j). It captures packets directly from a network interface, applies filters (protocol, source/destination ports), and prints or logs detailed information in a human-readable format.

## Features

- Captures live packets from the first available network interface
- Supports **protocol filtering**: `tcp`, `udp`, `icmp`, or `all`
- Supports **source/destination port filtering** for TCP/UDP traffic
- Prints detailed packet metadata (timestamps, IPs, ports, flags, sequence/ack numbers, etc.)
- Can log output to a file for later analysis

## Requirements

- Java 11+
- [pcap4j library](https://github.com/kaitoy/pcap4j)
- Native packet capture support (WinPcap/Npcap on Windows, libpcap on Linux/macOS)

## Build

Clone the project and build with Maven/Gradle, or package into a runnable JAR:

```bash
mvn clean package
```

This produces:

```bash
target/sniffer.jar
```

## Usage

```bash
java -jar sniffer.jar [options]
```