package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"time"
)

var seqNum uint32 = 0

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
func createIPFIXMessage(nodes []IoamNode) ([]byte, error) {
	var buf bytes.Buffer

	// IPFIX Header
	ipfixHeader := IPFIXHeader{
		Version:    IPFIX_VERSION,
		Length:     0, // Placeholder, will be updated later
		ExportTime: uint32(time.Now().Unix()),
		SeqNumber:  seqNum,
		DomainID:   IPFIX_DOMAIN_ID,
	}
	if err := binary.Write(&buf, binary.BigEndian, ipfixHeader); err != nil {
		return nil, err
	}

	// IPFIX Template Set
	var template, fieldCount, err = createIOAMTemplateSet(nodes[0].TraceType, nodes[0].hasDexFlowID, nodes[0].hasDexSeqNum)
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
	for _, d := range nodes {
		encodeIoam(&buf, d)
		seqNum += uint32(fieldCount)
	}

	// Update length in IPFIX header (total length of the message)
	packet := buf.Bytes()
	setLength := len(packet) - setHeaderPos
	binary.BigEndian.PutUint16(packet[setHeaderPos+2:setHeaderPos+4], uint16(setLength))

	// Update total message length in the IPFIX header
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))

	return packet, nil
}

// Creates an IPFIX template set for IOAM
func createIOAMTemplateSet(traceType uint32, hasDexFlowID bool, hasDexSeqNum bool) ([]byte, uint16, error) {
	var buf bytes.Buffer
	var fieldCount uint16 = 1
	var fields []IPFIXFieldSpecifier

	// Add the Namespace field
	fields = append(fields, IPFIXFieldSpecifier{FieldId: 0 | 0x8000, FieldLen: 2})

	// Add fields based on the trace type
	if traceType&TRACE_TYPE_BIT0_MASK != 0 || traceType&TRACE_TYPE_BIT8_MASK != 0 {
		fields = append(fields, IPFIXFieldSpecifier{FieldId: 1 | 0x8000, FieldLen: 1})
		fieldCount++
	}

	if traceType&TRACE_TYPE_BIT0_MASK != 0 {
		fields = append(fields, IPFIXFieldSpecifier{FieldId: 2 | 0x8000, FieldLen: 3})
		fieldCount++
	}

	if traceType&TRACE_TYPE_BIT1_MASK != 0 {
		fields = append(fields, IPFIXFieldSpecifier{FieldId: 3 | 0x8000, FieldLen: 2})
		fields = append(fields, IPFIXFieldSpecifier{FieldId: 4 | 0x8000, FieldLen: 2})
		fieldCount += 2
	}

	if traceType&TRACE_TYPE_BIT2_MASK != 0 {
		fields = append(fields, IPFIXFieldSpecifier{FieldId: 5 | 0x8000, FieldLen: 4})
		fieldCount++
	}

	if traceType&TRACE_TYPE_BIT3_MASK != 0 {
		fields = append(fields, IPFIXFieldSpecifier{FieldId: 6 | 0x8000, FieldLen: 4})
		fieldCount++
	}

	if traceType&TRACE_TYPE_BIT5_MASK != 0 {
		fields = append(fields, IPFIXFieldSpecifier{FieldId: 7 | 0x8000, FieldLen: 4})
		fieldCount++
	}

	if traceType&TRACE_TYPE_BIT6_MASK != 0 {
		fields = append(fields, IPFIXFieldSpecifier{FieldId: 8 | 0x8000, FieldLen: 4})
		fieldCount++
	}

	if traceType&TRACE_TYPE_BIT8_MASK != 0 {
		fields = append(fields, IPFIXFieldSpecifier{FieldId: 9 | 0x8000, FieldLen: 7})
		fieldCount++
	}

	if traceType&TRACE_TYPE_BIT9_MASK != 0 {
		fields = append(fields, IPFIXFieldSpecifier{FieldId: 10 | 0x8000, FieldLen: 4})
		fields = append(fields, IPFIXFieldSpecifier{FieldId: 11 | 0x8000, FieldLen: 4})
		fieldCount += 2
	}

	if traceType&TRACE_TYPE_BIT10_MASK != 0 {
		fields = append(fields, IPFIXFieldSpecifier{FieldId: 12 | 0x8000, FieldLen: 8})
		fieldCount++
	}

	// Opaque State Snapshot (variable length)
	if traceType&TRACE_TYPE_BIT22_MASK != 0 {
		fields = append(fields, IPFIXFieldSpecifier{FieldId: (13 | 0x8000), FieldLen: 3})
		fields = append(fields, IPFIXFieldSpecifier{FieldId: (14 | 0x8000), FieldLen: 65535})
		fieldCount += 2
	}

	if hasDexFlowID {
		fields = append(fields, IPFIXFieldSpecifier{FieldId: (15 | 0x8000), FieldLen: 4})
		fieldCount++
	}

	if hasDexSeqNum {
		fields = append(fields, IPFIXFieldSpecifier{FieldId: (16 | 0x8000), FieldLen: 4})
		fieldCount++
	}

	// Template Set Header
	templateSetHeader := IPFIXSetHeader{
		SetId:     2, // 2 is the ID for a template set
		SetLength: 0, // Placeholder, will be updated later
	}
	setHeaderPos := buf.Len() // Save position to update set length later

	if err := binary.Write(&buf, binary.BigEndian, templateSetHeader); err != nil {
		return nil, 0, err
	}

	// Template Fields
	template := IPFIXTemplateRecord{
		TemplateId: TEMPLATE_ID, // Unique Template ID for IOAM Data
		FieldCount: fieldCount,
		Fields:     fields,
	}

	// Write Template ID and Field Count
	if err := binary.Write(&buf, binary.BigEndian, template.TemplateId); err != nil {
		return nil, 0, err
	}
	if err := binary.Write(&buf, binary.BigEndian, template.FieldCount); err != nil {
		return nil, 0, err
	}

	// Write Field Specifiers to the buffer
	for _, field := range template.Fields {
		if err := binary.Write(&buf, binary.BigEndian, field); err != nil {
			return nil, 0, err
		}
		// Write enterprise ID
		if err := binary.Write(&buf, binary.BigEndian, uint32(ULIEGE_PEN_IANA)); err != nil {
			return nil, 0, err
		}
	}

	// Update Set Length in the Template Set Header
	packet := buf.Bytes()
	setLength := len(packet) - setHeaderPos
	binary.BigEndian.PutUint16(packet[setHeaderPos+2:setHeaderPos+4], uint16(setLength))

	return packet, fieldCount, nil
}

// Encodes an IOAMData struct into a byte slice
func encodeIoam(buf *bytes.Buffer, d IoamNode) {
	binary.Write(buf, binary.BigEndian, d.Namespace)

	if d.TraceType&TRACE_TYPE_BIT0_MASK != 0 || d.TraceType&TRACE_TYPE_BIT8_MASK != 0 {
		buf.WriteByte(d.HopLimit)
	}

	if d.TraceType&TRACE_TYPE_BIT0_MASK != 0 {
		binary.Write(buf, binary.BigEndian, []byte{
			byte(d.NodeId),
			byte(d.NodeId >> 8),
			byte(d.NodeId >> 16),
		}) // 24-bit Node ID
	}

	if d.TraceType&TRACE_TYPE_BIT1_MASK != 0 {
		binary.Write(buf, binary.BigEndian, d.IngressId)
		binary.Write(buf, binary.BigEndian, d.EgressId)
	}

	if d.TraceType&TRACE_TYPE_BIT2_MASK != 0 {
		binary.Write(buf, binary.BigEndian, d.TimestampSecs)
	}

	if d.TraceType&TRACE_TYPE_BIT3_MASK != 0 {
		binary.Write(buf, binary.BigEndian, d.TimestampFrac)
	}

	if d.TraceType&TRACE_TYPE_BIT5_MASK != 0 {
		binary.Write(buf, binary.BigEndian, d.NamespaceData)
	}

	if d.TraceType&TRACE_TYPE_BIT6_MASK != 0 {
		binary.Write(buf, binary.BigEndian, d.QueueDepth)
	}

	if d.TraceType&TRACE_TYPE_BIT8_MASK != 0 {
		binary.Write(buf, binary.BigEndian, []byte{
			byte(d.NodeIdWide),
			byte(d.NodeIdWide >> 8),
			byte(d.NodeIdWide >> 16),
			byte(d.NodeIdWide >> 24),
			byte(d.NodeIdWide >> 32),
			byte(d.NodeIdWide >> 40),
			byte(d.NodeIdWide >> 48),
		}) // 56-bit IdWide
	}

	if d.TraceType&TRACE_TYPE_BIT9_MASK != 0 {
		binary.Write(buf, binary.BigEndian, d.IngressIdWide)
		binary.Write(buf, binary.BigEndian, d.EgressIdWide)
	}

	if d.TraceType&TRACE_TYPE_BIT10_MASK != 0 {
		binary.Write(buf, binary.BigEndian, d.NamespaceDataWide)
	}

	if d.TraceType&TRACE_TYPE_BIT22_MASK != 0 {
		binary.Write(buf, binary.BigEndian, []byte{
			byte(d.OssSchema),
			byte(d.OssSchema >> 8),
			byte(d.OssSchema >> 16),
		})

		// Write Snapshot length
		var realOssLen uint16 = uint16(len(d.Snapshot))
		if realOssLen < 255 {
			buf.WriteByte(uint8(realOssLen))
		} else {
			buf.WriteByte(255)
			binary.Write(buf, binary.BigEndian, []byte{
				byte(realOssLen),
				byte(realOssLen >> 8),
			})
		}

		// Write Snapshot data
		buf.Write(d.Snapshot)
	}

	if d.hasDexFlowID {
		binary.Write(buf, binary.BigEndian, d.DexFlowID)
	}

	if d.hasDexSeqNum {
		binary.Write(buf, binary.BigEndian, d.DexSeqNum)
	}
}
