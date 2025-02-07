package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"time"
)

// sendIPFIX sends the IPFIX message over UDP
func sendIPFIX(data []IOAMData) error {
	ipfixMsg, err := createIPFIXMessage(data)
	if err != nil {
		log.Printf("failed to create IPFIX message: %v", err)
		return err
	}

	// Send IPFIX message via UDP
	conn, err := net.Dial("udp", collectorAddr)
	if err != nil {
		log.Printf("failed to establish UDP connection: %v", err)
		return err
	}
	defer conn.Close()

	_, err = conn.Write(ipfixMsg)

	return err
}

// createIPFIXMessage creates an IPFIX message from IOAMData
func createIPFIXMessage(data []IOAMData) ([]byte, error) {
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
	templateSet, err := createIOAMTemplateSet()
	if err != nil {
		log.Printf("failed to create template set: %v", err)
		return nil, err
	}
	buf.Write(templateSet)

	// IPFIX Set Header
	setHeader := IPFIXSetHeader{
		SetId:     TEMPLATE_ID,
		SetLength: 0, // Placeholder, will be updated later
	}
	setHeaderPos := buf.Len() // Save position to update set length later

	if err := binary.Write(&buf, binary.BigEndian, setHeader); err != nil {
		return nil, err
	}

	// For each IOAMData in the slice, encode the data and append it to the IPFIX message
	for _, d := range data {
		encodeIOAMData(&buf, d)
	}

	// Update length in IPFIX header (total length of the message)
	packet := buf.Bytes()
	setLength := len(packet) - setHeaderPos
	binary.BigEndian.PutUint16(packet[setHeaderPos+2:setHeaderPos+4], uint16(setLength))

	// Update total message length in the IPFIX header
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))

	// Increment seqNum
	seqNum += uint32(len(data))

	return packet, nil
}

// createIOAMTemplateSet creates an IPFIX template set for IOAM
func createIOAMTemplateSet() ([]byte, error) {
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

	// Define the Template ID and field specifiers for IOAM data
	templateRecord := IPFIXTemplateRecord{
		TemplateId: TEMPLATE_ID, // Unique Template ID for IOAM Data
		FieldCount: 17,          // Including the Snapshot field, which is variable-length and enterprise-specific
		Fields: []IPFIXFieldSpecifier{
			{FieldId: (0 | 0x8000), FieldLen: 4},      // TraceType (4 bytes)
			{FieldId: (1 | 0x8000), FieldLen: 1},      // HopLimit (1 byte)
			{FieldId: (2 | 0x8000), FieldLen: 3},      // NodeId (24 bits => 3 bytes)
			{FieldId: (3 | 0x8000), FieldLen: 2},      // IngressId (2 bytes)
			{FieldId: (4 | 0x8000), FieldLen: 2},      // EgressId (2 bytes)
			{FieldId: (5 | 0x8000), FieldLen: 4},      // TimestampSecs (4 bytes)
			{FieldId: (6 | 0x8000), FieldLen: 4},      // TimestampFrac (4 bytes)
			{FieldId: (7 | 0x8000), FieldLen: 4},      // TransitDelay (4 bytes)
			{FieldId: (8 | 0x8000), FieldLen: 4},      // NamespaceData (4 bytes)
			{FieldId: (9 | 0x8000), FieldLen: 4},      // QueueDepth (4 bytes)
			{FieldId: (10 | 0x8000), FieldLen: 4},     // CsumComp (4 bytes)
			{FieldId: (11 | 0x8000), FieldLen: 7},     // IdWide (56 bits => 7 bytes)
			{FieldId: (12 | 0x8000), FieldLen: 4},     // IngressIdWide (4 bytes)
			{FieldId: (13 | 0x8000), FieldLen: 4},     // EgressIdWide (4 bytes)
			{FieldId: (14 | 0x8000), FieldLen: 8},     // NamespaceDataWide (8 bytes)
			{FieldId: (15 | 0x8000), FieldLen: 4},     // BufferOccupancy (4 bytes)
			{FieldId: (16 | 0x8000), FieldLen: 65535}, // Opaque State Snapshot (variable length)
		},
	}

	// Write Template ID and Field Count
	if err := binary.Write(&buf, binary.BigEndian, templateRecord.TemplateId); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, templateRecord.FieldCount); err != nil {
		return nil, err
	}

	// Write Field Specifiers to the buffer
	for _, field := range templateRecord.Fields {
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

// encodeIOAMData encodes an IOAMData struct into a byte slice
func encodeIOAMData(buf *bytes.Buffer, d IOAMData) {
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
	binary.Write(buf, binary.BigEndian, d.TransitDelay)
	binary.Write(buf, binary.BigEndian, d.NamespaceData)
	binary.Write(buf, binary.BigEndian, d.QueueDepth)
	binary.Write(buf, binary.BigEndian, d.CsumComp)
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
	binary.Write(buf, binary.BigEndian, d.BufferOccupancy)

	// Write Snapshot variable element
	buf.WriteByte(4 * d.OssLen)
	if d.Snapshot != nil {
		buf.Write(d.Snapshot)
	}
}
