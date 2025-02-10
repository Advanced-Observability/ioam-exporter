package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"time"
)

// Sends the IPFIX message over UDP
func sendIPFIX(msg []byte) error {
	// Send IPFIX message via UDP
	conn, err := net.Dial("udp", collectorAddr)
	if err != nil {
		log.Printf("failed to establish UDP connection: %v", err)
		return err
	}
	defer conn.Close()

	_, err = conn.Write(msg)

	return err
}

// Creates an IPFIX message containing the given data for the given ioam optionType
func createIPFIXMessage(data bytes.Buffer, optionType int) ([]byte, error) {
	var buf bytes.Buffer

	// IPFIX Header
	ipfixHeader := IPFIXHeader{
		Version:    10,
		Length:     0, // Placeholder, will be updated later
		ExportTime: uint32(time.Now().Unix()),
		SeqNumber:  seqNum,
		DomainID:   IPFIX_DOMAIN_ID,
	}
	if err := binary.Write(&buf, binary.BigEndian, ipfixHeader); err != nil {
		return nil, err
	}

	// IPFIX Template Set
	var template []byte
	var err error
	if optionType == IOAM6_EVENT_TYPE_TRACE {
		template, err = createIOAMTemplateSet(ioamPtoTemplate)
	} else if optionType == IOAM6_EVENT_TYPE_DEX {
		template, err = createIOAMTemplateSet(ioamDexTemplate)
	}
	if err != nil {
		log.Printf("failed to create template set: %v", err)
		return nil, err
	}
	buf.Write(template)

	// IPFIX Set Header
	setHeader := IPFIXSetHeader{
		SetId:     TEMPLATE_ID,
		SetLength: 0, // Placeholder, will be updated later
	}
	setHeaderPos := buf.Len() // Save position to update set length later

	if err := binary.Write(&buf, binary.BigEndian, setHeader); err != nil {
		return nil, err
	}

	// Write node data
	buf.Write(data.Bytes())

	// Update length in IPFIX header (total length of the message)
	packet := buf.Bytes()
	setLength := len(packet) - setHeaderPos
	binary.BigEndian.PutUint16(packet[setHeaderPos+2:setHeaderPos+4], uint16(setLength))

	// Update total message length in the IPFIX header
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))

	// Increment seqNum
	seqNum += uint32(data.Len())

	return packet, nil
}

// Creates an IPFIX template set for IOAM
func createIOAMTemplateSet(template IPFIXTemplateRecord) ([]byte, error) {
	var buf bytes.Buffer

	// Template Set Header
	templateSetHeader := IPFIXSetHeader{
		SetId:     2, // 2 is the ID for a template set
		SetLength: 0, // Placeholder, will be updated later
	}
	setHeaderPos := buf.Len() // Save position to update set length later

	if err := binary.Write(&buf, binary.BigEndian, templateSetHeader); err != nil {
		return nil, err
	}

	// Write Template ID and Field Count
	if err := binary.Write(&buf, binary.BigEndian, template.TemplateId); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, template.FieldCount); err != nil {
		return nil, err
	}

	// Write Field Specifiers to the buffer
	for _, field := range template.Fields {
		if err := binary.Write(&buf, binary.BigEndian, field); err != nil {
			return nil, err
		}
		// Write enterprise ID
		if err := binary.Write(&buf, binary.BigEndian, uint32(ULIEGE_PEN_IANA)); err != nil {
			return nil, err
		}
	}

	// Update Set Length in the Template Set Header
	packet := buf.Bytes()
	setLength := len(packet) - setHeaderPos
	binary.BigEndian.PutUint16(packet[setHeaderPos+2:setHeaderPos+4], uint16(setLength))

	return packet, nil
}

// Encodes an IOAMData struct into a byte slice
func encodeIoamPto(buf *bytes.Buffer, d IoamNodePTO) {
	binary.Write(buf, binary.BigEndian, d.TraceType)
	buf.WriteByte(d.HopLimit)
	binary.Write(buf, binary.BigEndian, []byte{
		byte(d.NodeId),
		byte(d.NodeId >> 8),
		byte(d.NodeId >> 16),
	}) // 24-bit Node ID
	binary.Write(buf, binary.BigEndian, d.IngressId)
	binary.Write(buf, binary.BigEndian, d.EgressId)
	binary.Write(buf, binary.BigEndian, d.TimestampSecs)
	binary.Write(buf, binary.BigEndian, d.TimestampFrac)
	binary.Write(buf, binary.BigEndian, d.NamespaceData)
	binary.Write(buf, binary.BigEndian, d.QueueDepth)
	binary.Write(buf, binary.BigEndian, []byte{
		byte(d.IdWide),
		byte(d.IdWide >> 8),
		byte(d.IdWide >> 16),
		byte(d.IdWide >> 24),
		byte(d.IdWide >> 32),
		byte(d.IdWide >> 40),
		byte(d.IdWide >> 48),
	}) // 56-bit IdWide
	binary.Write(buf, binary.BigEndian, d.IngressIdWide)
	binary.Write(buf, binary.BigEndian, d.EgressIdWide)
	binary.Write(buf, binary.BigEndian, d.NamespaceDataWide)

	// Write Snapshot variable element
	buf.WriteByte(4 * d.OssLen)
	binary.Write(buf, binary.BigEndian, d.OssSchema)
	if d.Snapshot != nil {
		buf.Write(d.Snapshot)
	}
}

// Encodes an IOAMData struct into a byte slice
func encodeIoamDex(buf *bytes.Buffer, d IoamNodeDEX) {
	binary.Write(buf, binary.BigEndian, d.Namespace)
	binary.Write(buf, binary.BigEndian, d.DexFlowID)
	binary.Write(buf, binary.BigEndian, d.DexSeqNum)
	binary.Write(buf, binary.BigEndian, d.HopLimit)
	binary.Write(buf, binary.BigEndian, d.NodeId)
	binary.Write(buf, binary.BigEndian, d.IngressId)
	binary.Write(buf, binary.BigEndian, d.EgressId)
	binary.Write(buf, binary.BigEndian, d.TimestampSecs)
	binary.Write(buf, binary.BigEndian, d.TimestampFrac)
	binary.Write(buf, binary.BigEndian, d.NamespaceData)
	binary.Write(buf, binary.BigEndian, d.QueueDepth)
	binary.Write(buf, binary.BigEndian, d.HopLimitWide)
	binary.Write(buf, binary.BigEndian, d.NodeIdWide)
	binary.Write(buf, binary.BigEndian, d.IngressIdWide)
	binary.Write(buf, binary.BigEndian, d.EgressIdWide)
	binary.Write(buf, binary.BigEndian, d.NamespaceDataWide)
	if d.Snapshot != nil {
		binary.Write(buf, binary.BigEndian, d.OssSchema)
		buf.Write(d.Snapshot)
	}
}
