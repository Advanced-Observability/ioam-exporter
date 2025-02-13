package main

import (
	"encoding/binary"
	"errors"
	"log"

	"github.com/mdlayher/netlink"
)

func extractDexData(attrs []netlink.Attribute) (IoamNode, error) {
	var node IoamNode

	for _, attr := range attrs {
		switch attr.Type {
		case IOAM6_EVENT_ATTR_OPTION_TYPE:
			if attr.Data[0] != 4 {
				return IoamNode{}, errors.New("Not DEX event")
			}
		case IOAM6_EVENT_ATTR_DEX_NAMESPACE:
			node.Namespace = binary.LittleEndian.Uint16(attr.Data)
		case IOAM6_EVENT_ATTR_DEX_FLOW_ID:
			node.DexFlowID = binary.LittleEndian.Uint32(attr.Data)
			node.hasDexFlowID = true
		case IOAM6_EVENT_ATTR_DEX_SEQ_NUM:
			node.DexSeqNum = binary.LittleEndian.Uint32(attr.Data)
			node.hasDexSeqNum = true
		case IOAM6_EVENT_ATTR_DEX_DATA_HOP_LIM_NODE_ID:
			node.HopLimit = uint8(attr.Data[0])
			node.NodeId = binary.BigEndian.Uint32(attr.Data) & 0xFFFFFF
			node.TraceType |= TRACE_TYPE_BIT0_MASK
		case IOAM6_EVENT_ATTR_DEX_DATA_INGRESS_EGRESS_INTERFACES:
			node.IngressId = binary.BigEndian.Uint16(attr.Data[0:2])
			node.EgressId = binary.BigEndian.Uint16(attr.Data[2:4])
			node.TraceType |= TRACE_TYPE_BIT1_MASK
		case IOAM6_EVENT_ATTR_DEX_DATA_TIMESTAMP:
			node.TimestampSecs = binary.BigEndian.Uint32(attr.Data)
			node.TraceType |= TRACE_TYPE_BIT2_MASK
		case IOAM6_EVENT_ATTR_DEX_DATA_TIMESTAMP_FRAC:
			node.TimestampFrac = binary.BigEndian.Uint32(attr.Data)
			node.TraceType |= TRACE_TYPE_BIT3_MASK
		case IOAM6_EVENT_ATTR_DEX_DATA_NAMESPACE_SPECIFIC:
			node.NamespaceData = binary.BigEndian.Uint32(attr.Data)
			node.TraceType |= TRACE_TYPE_BIT5_MASK
		case IOAM6_EVENT_ATTR_DEX_DATA_QUEUE_DEPTH:
			node.QueueDepth = binary.BigEndian.Uint32(attr.Data)
			node.TraceType |= TRACE_TYPE_BIT6_MASK
		case IOAM6_EVENT_ATTR_DEX_DATA_HOP_LIM_NODE_ID_WIDE:
			node.HopLimit = uint8(attr.Data[0])
			node.NodeIdWide = binary.BigEndian.Uint64(attr.Data) & 0xFFFFFFFFFFFFFF
			node.TraceType |= TRACE_TYPE_BIT8_MASK
		case IOAM6_EVENT_ATTR_DEX_DATA_INGRESS_EGRESS_INTERFACES_WIDE:
			node.IngressIdWide = binary.BigEndian.Uint32(attr.Data[0:4])
			node.EgressIdWide = binary.BigEndian.Uint32(attr.Data[4:8])
			node.TraceType |= TRACE_TYPE_BIT9_MASK
		case IOAM6_EVENT_ATTR_DEX_DATA_NAMESPACE_SPECIFIC_WIDE:
			node.NamespaceDataWide = binary.BigEndian.Uint64(attr.Data)
			node.TraceType |= TRACE_TYPE_BIT10_MASK
		case IOAM6_EVENT_ATTR_DEX_OSS_SCID:
			node.OssSchema = binary.BigEndian.Uint32(attr.Data)
		case IOAM6_EVENT_ATTR_DEX_OSS_DATA:
			node.Snapshot = attr.Data
			node.OssLen = uint8(len(node.Snapshot) / 4)
			node.TraceType |= TRACE_TYPE_BIT22_MASK
		default:
			log.Println("Unexpected attribute")
		}
	}

	return node, nil
}
