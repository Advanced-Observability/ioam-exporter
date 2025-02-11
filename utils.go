package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

// Parse CLI options
func parseCliOptions() {
	// Argument parsing
	flag.StringVar(&collectorAddr, "c", "", "Collector address and port (addr:port) for UDP transmission")
	flag.BoolVar(&consoleOut, "o", false, "Print traces to console")
	showHelp := flag.Bool("h", false, "View help")
	flag.Parse()

	if *showHelp {
		flag.PrintDefaults()
		os.Exit(0)
	}
	if collectorAddr == "" && !consoleOut {
		fmt.Println("Use a collector or console print")
		flag.PrintDefaults()
		os.Exit(1)
	}
}

// Setup generic netlink listener on multicast group
func setupListener() *genetlink.Conn {
	// Genetlink connection
	conn, err := genetlink.Dial(nil)
	if err != nil {
		log.Fatalf("failed to create genetlink connection: %v", err)
	}

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

	return conn
}
