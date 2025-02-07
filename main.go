package main

import (
	"flag"
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
	// Argument parsing
	flag.StringVar(&collectorAddr, "c", "", "Collector address and port (addr:port) for UDP transmission")
	flag.BoolVar(&consoleOut, "o", false, "Print traces to console")
	showHelp := flag.Bool("h", false, "View help")
	flag.Parse()

	if *showHelp || (collectorAddr == "" && !consoleOut) {
		flag.PrintDefaults()
		return
	}

	// Genetlink connection
	conn, err := genetlink.Dial(nil)
	if err != nil {
		log.Fatalf("failed to create genetlink connection: %v", err)
	}
	defer conn.Close()

	// Set read buffer to 0 bytes to avoid data desynchronizations
	conn.SetReadBuffer(0)
	// Disable acknowledgements to save bandwidth
	conn.SetOption(netlink.CapAcknowledge, false)

	// Get genetlink IOAM6 family ID
	family, err := conn.GetFamily(IOAM6_GENL_NAME)
	if err != nil {
		log.Fatalf("failed to get genetlink family: %v", err)
	}

	var IOAM6_GENL_GROUP_ID uint32 = 0
	for _, group := range family.Groups {
		if group.Name == IOAM6_GENL_GROUP_NAME {
			IOAM6_GENL_GROUP_ID = group.ID
			break
		}
	}

	if IOAM6_GENL_GROUP_ID == 0 {
		log.Fatalf("failed to get multicast group " + IOAM6_GENL_GROUP_NAME)
	}

	// Subscribe to multicast group
	if err := conn.JoinGroup(IOAM6_GENL_GROUP_ID); err != nil {
		log.Fatalf("failed to subscribe to multicast group: %v", err)
	}

	go writeStats(STATS_FILE)
	fmt.Println("[IOAM exporter] Started...")

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
	if msg.Header.Command != IOAM6_EVENT_TYPE_TRACE {
		return nil
	}

	attrs, err := netlink.UnmarshalAttributes(msg.Data)
	if err != nil {
		log.Printf("failed to parse attributes: %v", err)
		return err
	}

	nodes, err := extractPtoData(attrs)
	if err != nil {
		log.Printf("failed to build IOAMdata: %v", err)
		return err
	}

	if consoleOut {
		printNodes(nodes)
	}

	if collectorAddr != "" {
		sendIPFIX(nodes)
	}

	ioamCount++

	return nil
}

// Prints the IOAMData structs to the console
func printNodes(nodes []IOAMData) {
	for _, node := range nodes {
		fmt.Printf("%+v\n", node)

		if node.Snapshot != nil {
			fmt.Printf("Snapshot: %s\n", string(node.Snapshot))
		}

		fmt.Printf("\n")
	}
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
