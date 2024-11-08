package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"
)

const (
	STATS_FILE = "./exporterStats"

	ULIEGE_PEN_IANA = 10383
	TEMPLATE_ID     = 293 // Must be higher than 255 (arbitrary)
	IPFIX_DOMAIN_ID = 1

	IOAM6_GENL_NAME                  string = "IOAM6"
	IOAM6_GENL_GROUP_NAME            string = "ioam6_events"
	IOAM6_EVENT_TRACE                       = 1
	IOAM6_EVENT_ATTR_TRACE_NAMESPACE        = 1
	IOAM6_EVENT_ATTR_TRACE_NODELEN          = 2
	IOAM6_EVENT_ATTR_TRACE_TYPE             = 3
	IOAM6_EVENT_ATTR_TRACE_DATA             = 4

	traceTypeBit0Mask  = 1 << 23
	traceTypeBit1Mask  = 1 << 22
	traceTypeBit2Mask  = 1 << 21
	traceTypeBit3Mask  = 1 << 20
	traceTypeBit4Mask  = 1 << 19
	traceTypeBit5Mask  = 1 << 18
	traceTypeBit6Mask  = 1 << 17
	traceTypeBit7Mask  = 1 << 16
	traceTypeBit8Mask  = 1 << 15
	traceTypeBit9Mask  = 1 << 14
	traceTypeBit10Mask = 1 << 13
	traceTypeBit11Mask = 1 << 12
	traceTypeBit22Mask = 1 << 1
)

var (
	SEQ_NUM                uint32 = 0
	COLLECTOR_ADDR         string
	CONSOLE_OUT            bool
	IOAM_MESSAGE_COUNT     uint64 = 0
	OVERFLOW_MESSAGE_COUNT uint64 = 0
)

func main() {
	// Argument parsing
	flag.StringVar(&COLLECTOR_ADDR, "c", "", "Collector address and port (addr:port) for UDP transmission")
	flag.BoolVar(&CONSOLE_OUT, "o", false, "Print traces to console")
	showHelp := flag.Bool("h", false, "View help")
	flag.Parse()
	if *showHelp || (COLLECTOR_ADDR == "" && !CONSOLE_OUT) {
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
			OVERFLOW_MESSAGE_COUNT++
		}

		for _, msg := range messages {
			go readMessage(msg)
		}
	}
}

// readMessage parses the netlink message and extracts IOAMData
func readMessage(msg genetlink.Message) error {
	if msg.Header.Command != IOAM6_EVENT_TRACE {
		return nil
	}

	attrs, err := netlink.UnmarshalAttributes(msg.Data)
	if err != nil {
		log.Printf("failed to parse attributes: %v", err)
		return err
	}

	nodes, err := extractIOAMData(attrs)
	if err != nil {
		log.Printf("failed to build IOAMdata: %v", err)
		return err
	}

	if CONSOLE_OUT {
		printNodes(nodes)
	}
	sendIPFIX(nodes)

	IOAM_MESSAGE_COUNT++

	return nil
}

// printNodes prints the IOAMData structs to the console
func printNodes(nodes []IOAMData) {
	for _, node := range nodes {
		fmt.Printf("TraceType: %x, NodeId: %d, IngressId: %d, EgressId: %d, Timestamp: %d.%d, TransitDelay: %d, NamespaceData: %d, QueueDepth: %d, CsumComp: %d, IdWide: %d, IngressIdWide: %d, EgressIdWide: %d, NamespaceDataWide: %d, BufferOccupancy: %d, OssLen: %d, OssSchema: %d",
			node.TraceType, node.NodeId, node.IngressId, node.EgressId, node.TimestampSecs, node.TimestampFrac, node.TransitDelay, node.NamespaceData, node.QueueDepth, node.CsumComp, node.IdWide, node.IngressIdWide, node.EgressIdWide, node.NamespaceDataWide, node.BufferOccupancy, node.OssLen, node.OssSchema)
		if node.Snapshot != nil {
			fmt.Printf("\nSnapshot: %x", node.Snapshot)
		}
		fmt.Printf("\n")
	}
}

// extractIOAMData parses the netlink attributes into IOAMData structures
func extractIOAMData(attrs []netlink.Attribute) ([]IOAMData, error) {
	var nodeLen uint8
	var traceType uint32
	var data []byte
	for _, attr := range attrs {
		switch attr.Type {
		case IOAM6_EVENT_ATTR_TRACE_NAMESPACE:
			continue
		case IOAM6_EVENT_ATTR_TRACE_NODELEN:
			nodeLen = attr.Data[0]
		case IOAM6_EVENT_ATTR_TRACE_TYPE:
			traceType = binary.LittleEndian.Uint32(attr.Data) >> 8
		case IOAM6_EVENT_ATTR_TRACE_DATA:
			data = attr.Data
		}
	}

	var nodes []IOAMData
	offset := 0
	for offset < len(data) {
		node, err := parseNodeData(data[offset:offset+int(nodeLen)*4], traceType)
		node.TraceType = traceType
		if err != nil {
			return nil, err
		}
		offset += int(nodeLen) * 4

		if traceType&traceTypeBit22Mask != 0 {
			node.OssLen = data[offset]
			node.OssSchema = binary.BigEndian.Uint32(data[offset:offset+4]) & 0xFFFFFF
			if len(data[offset:]) < 4+int(node.OssLen)*4 {
				return nil, errors.New("invalid packet length")
			}
			node.Snapshot = data[4+offset : 4+node.OssLen*4]
			offset += 4 + int(node.OssLen)*4
		}

		nodes = append([]IOAMData{node}, nodes...)
	}

	return nodes, nil
}

// parseNodeData parses a node data into a IOAMData structure
func parseNodeData(data []byte, traceType uint32) (IOAMData, error) {
	node := IOAMData{}
	offset := 0

	if traceType&traceTypeBit0Mask != 0 {
		node.HopLimit = data[offset]
		node.NodeId = binary.BigEndian.Uint32(data[offset:offset+4]) & 0xFFFFFF
		offset += 4
	}
	if traceType&traceTypeBit1Mask != 0 {
		node.IngressId = uint16(binary.BigEndian.Uint16(data[offset : offset+2]))
		node.EgressId = uint16(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4
	}
	if traceType&traceTypeBit2Mask != 0 {
		node.TimestampSecs = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&traceTypeBit3Mask != 0 {
		node.TimestampFrac = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&traceTypeBit4Mask != 0 {
		node.TransitDelay = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&traceTypeBit5Mask != 0 {
		node.NamespaceData = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&traceTypeBit6Mask != 0 {
		node.QueueDepth = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&traceTypeBit7Mask != 0 {
		node.CsumComp = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&traceTypeBit8Mask != 0 {
		node.HopLimit = data[offset]
		node.IdWide = binary.BigEndian.Uint64(data[offset:offset+8]) & 0xFFFFFFFFFFFFFF
		offset += 8
	}
	if traceType&traceTypeBit9Mask != 0 {
		node.IngressIdWide = binary.BigEndian.Uint32(data[offset : offset+4])
		node.EgressIdWide = binary.BigEndian.Uint32(data[offset+4 : offset+8])
		offset += 8
	}
	if traceType&traceTypeBit10Mask != 0 {
		node.NamespaceDataWide = binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
	}
	if traceType&traceTypeBit11Mask != 0 {
		node.BufferOccupancy = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}

	return node, nil
}

// writeStats writes the number of received IOAM messages to a file
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
		if _, err := fmt.Fprintf(file, "IOAM messages\t%d\nOverflow errors\t%d\n", IOAM_MESSAGE_COUNT, OVERFLOW_MESSAGE_COUNT); err != nil {
			log.Fatalf("Error writing to stats file: %v", err)
		}
	}
}
