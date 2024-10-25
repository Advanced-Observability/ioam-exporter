# IOAM Exporter

This project provides a Go-based implementation for encoding and exporting IP Flow Information Export (IPFIX) messages of In-band Operations, Administration, and Maintenance (IOAM) data.
The exporter receives IOAM data from the Linux kernel using generic netlink events.
The IOAM traces are then encoded in IPFIX messages and sent to a specified collector using UDP.

## Project Structure

- `ipfix.go` – Contains functions and helpers to build and encode IPFIX messages, including creating IPFIX headers, templates, and encoding IOAM data.
- `ipfix_types.go` – Defines the structures used in IPFIX, such as `FieldSpecifier`, `TemplateRecord`, `Set`, `MessageHeader`, and related helper methods.
- `main.go` – Main application logic.

## Prerequisites

- [Go](https://go.dev/doc/install) (version 1.20 or higher)
- [Linux Kernel](https://www.kernel.org/) (version 6.9 or higher)

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
  ./ioam-exporter -c <COLLECTOR_IP>:<COLLECTOR_PORT> [-o]
  ```
