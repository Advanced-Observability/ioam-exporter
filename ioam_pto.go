package main

import (
	"encoding/binary"
	"errors"

	"github.com/mdlayher/netlink"
)

// Parses the netlink attributes for IOAM PTO
func extractPtoData(attrs []netlink.Attribute) ([]IoamNodePTO, error) {
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

	var nodes []IoamNodePTO
	offset := 0
	for offset < len(data) {
		node, err := parseIoamPtoNode(data[offset:offset+int(nodeLen)*4], traceType)
		node.TraceType = traceType
		if err != nil {
			return nil, err
		}
		offset += int(nodeLen) * 4

		if traceType&TRACE_TYPE_BIT22_MASK != 0 {
			node.OssLen = data[offset]
			if node.OssLen == 0 {
				offset += 4
				nodes = append(nodes, node)
				continue
			}

			node.OssSchema = binary.BigEndian.Uint32(data[offset:offset+4]) & 0xFFFFFF

			if len(data[offset:]) < 4+int(node.OssLen)*4 {
				return nil, errors.New("invalid packet length")
			}
			node.Snapshot = data[4+offset : 4+offset+int(node.OssLen)*4]
			offset += 4 + int(node.OssLen)*4
		}

		nodes = append(nodes, node)
	}

	return nodes, nil
}

// parseNodeData parses a node data into a IOAMData structure
func parseIoamPtoNode(data []byte, traceType uint32) (IoamNodePTO, error) {
	node := IoamNodePTO{}
	offset := 0

	if traceType&TRACE_TYPE_BIT0_MASK != 0 {
		node.HopLimit = data[offset]
		node.NodeId = binary.BigEndian.Uint32(data[offset:offset+4]) & 0xFFFFFF
		offset += 4
	}
	if traceType&TRACE_TYPE_BIT1_MASK != 0 {
		node.IngressId = uint16(binary.BigEndian.Uint16(data[offset : offset+2]))
		node.EgressId = uint16(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4
	}
	if traceType&TRACE_TYPE_BIT2_MASK != 0 {
		node.TimestampSecs = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&TRACE_TYPE_BIT3_MASK != 0 {
		node.TimestampFrac = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&TRACE_TYPE_BIT5_MASK != 0 {
		node.NamespaceData = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&TRACE_TYPE_BIT6_MASK != 0 {
		node.QueueDepth = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if traceType&TRACE_TYPE_BIT8_MASK != 0 {
		node.HopLimit = data[offset]
		node.IdWide = binary.BigEndian.Uint64(data[offset:offset+8]) & 0xFFFFFFFFFFFFFF
		offset += 8
	}
	if traceType&TRACE_TYPE_BIT9_MASK != 0 {
		node.IngressIdWide = binary.BigEndian.Uint32(data[offset : offset+4])
		node.EgressIdWide = binary.BigEndian.Uint32(data[offset+4 : offset+8])
		offset += 8
	}
	if traceType&TRACE_TYPE_BIT10_MASK != 0 {
		node.NamespaceDataWide = binary.BigEndian.Uint64(data[offset : offset+8])
		offset += 8
	}

	return node, nil
}
