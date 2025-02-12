package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

var (
	seqNum        uint32 = 0
	collectorAddr string = ""
	consoleOut    bool   = false
	ioamCount     uint64 = 0
	overflowCount uint64 = 0
)

func main() {
	parseCliOptions()

	conn := setupListener()
	defer conn.Close()

	go writeStats(STATS_FILE)
	log.Println("[IOAM Exporter] Started...")

	// Message receiving loop
	for {
		messages, _, err := conn.Receive()
		if err != nil {
			// Assume that the error is due to a buffer overflow (ENOBUFS)
			overflowCount++
		}

		for _, msg := range messages {
			go readMessage(msg)
		}
	}
}

// Parses the netlink message and extracts IOAMData
func readMessage(msg genetlink.Message) error {
	attrs, err := netlink.UnmarshalAttributes(msg.Data)
	if err != nil {
		log.Printf("failed to parse attributes: %v", err)
		return err
	}

	var nodes []IoamNode
	if msg.Header.Command == IOAM6_EVENT_TYPE_TRACE {
		nodes, err = extractPtoData(attrs)
		if err != nil {
			log.Printf("failed to build IOAMdata: %v", err)
			return err
		}
	} else if msg.Header.Command == IOAM6_EVENT_TYPE_DEX {
		node, err := extractDexData(attrs)
		if err != nil {
			log.Printf("failed to build IoamNodeDEX: %d\n", err)
			return err
		}
		nodes = append(nodes, node)
	} else {
		log.Println(("unexpected generic netlink command"))
		return nil
	}

	if consoleOut {
		for _, node := range nodes {
			fmt.Printf("%+v\n\n", node)
		}
	}

	if collectorAddr != "" {
		var data bytes.Buffer
		for _, d := range nodes {
			encodeIoam(&data, d)
		}
		msg, err := createIPFIXMessage(data, nodes[0].TraceType, nodes[0].isDex)
		if err != nil {
			log.Printf("could not create ipfix message: %v", err)
			return err
		}
		sendIPFIX(msg)
	}

	ioamCount++

	return nil
}

// Writes the number of received IOAM messages to a file
func writeStats(fileName string) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	file, err := os.OpenFile(fileName, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		log.Fatalf("Error opening stats file: %v", err)
	}
	defer file.Close()

	for range ticker.C {
		// Update file statistics
		file.Seek(0, io.SeekStart)
		if _, err := fmt.Fprintf(file, "IOAM messages\t%d\nOverflow errors\t%d\n", ioamCount, overflowCount); err != nil {
			log.Fatalf("Error writing to stats file: %v", err)
		}
	}
}
