# IOAM Exporter

This project provides a Go-based implementation for encoding and exporting IP Flow Information Export (IPFIX) messages of In Situ Operations, Administration, and Maintenance (IOAM) data.

The exporter receives IOAM data from the Linux kernel using generic netlink multicast events.

Then, the IOAM traces are encoded in IPFIX messages and/or print in the console.

Finally, the IPFIX messages are sent to a specified collector using UDP.

## Supported IOAM option-types

Currently, the exporter supports the following IOAM option-types:
- IOAM Pre-allocated Trace Option-type (PTO). See [RFC 9197](https://datatracker.ietf.org/doc/rfc9197/);
- IOAM Direct Exporting (DEX). See [RFC 9326](https://datatracker.ietf.org/doc/rfc9326/).

## Project Structure

- `main.go` – Main application;
- `ipfix.go` – Contains functions and helpers to build and encode IPFIX messages, including creating IPFIX headers, templates, and encoding IOAM data;
- `ipfix_types.go` – Defines the structures used in IPFIX, such as `FieldSpecifier`, `TemplateRecord`, and `Set`;
- `ioam_pto.go` - Converts IOAM PTO data received from the kernel over generic netlink to the internal representation;
- `ioam_dex.go` - Converts IOAM DEX data received from the kernel over generic netlink to the internal representation;
- `constants.go` - Constants used throughout the application;
- `utils.go` - Contains utilities used throughout the application.

## Prerequisites

- [Go](https://go.dev/doc/install) (version 1.20 or higher);
- [Linux Kernel](https://www.kernel.org/) (version 6.9 or higher). :warning: IOAM DEX is an ongoing piece of work and has not yet reached the mainline kernel. Our [implementation](https://github.com/Advanced-Observability/ioam-direct-exporting) is available online.

## Getting Started

1. **Clone the Repository**

  ```sh
  git clone https://github.com/Advanced-Observability/ioam-exporter.git
  cd ioam-exporter
  ```

2. **Build the Application**

  ```sh
  go build
  ```

3. **Run the Application**

  ```sh
  ./ioam-exporter [-c <COLLECTOR_IP>:<COLLECTOR_PORT>] [-o]
  ```
