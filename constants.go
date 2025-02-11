package main

const (
	STATS_FILE = "./exporterStats"

	ULIEGE_PEN_IANA = 10383
	TEMPLATE_ID     = 293 // Must be higher than 255 (arbitrary)
	IPFIX_DOMAIN_ID = 1

	IOAM6_GENL_NAME       string = "IOAM6"
	IOAM6_GENL_GROUP_NAME string = "ioam6_events"
)

// IOAM generic netlink command
const (
	IOAM6_EVENT_TYPE_TRACE = 1
	IOAM6_EVENT_TYPE_DEX   = 2
)

// IOAM generic netlink attribute types
const (
	IOAM6_EVENT_ATTR_TRACE_NAMESPACE = 1
	IOAM6_EVENT_ATTR_TRACE_NODELEN   = 2
	IOAM6_EVENT_ATTR_TRACE_TYPE      = 3
	IOAM6_EVENT_ATTR_TRACE_DATA      = 4

	IOAM6_EVENT_ATTR_OPTION_TYPE = 5

	IOAM6_EVENT_ATTR_DEX_NAMESPACE = 6
	IOAM6_EVENT_ATTR_DEX_FLOW_ID   = 7
	IOAM6_EVENT_ATTR_DEX_SEQ_NUM   = 8

	IOAM6_EVENT_ATTR_DEX_DATA_HOP_LIM_NODE_ID                = 9
	IOAM6_EVENT_ATTR_DEX_DATA_INGRESS_EGRESS_INTERFACES      = 10
	IOAM6_EVENT_ATTR_DEX_DATA_TIMESTAMP                      = 11
	IOAM6_EVENT_ATTR_DEX_DATA_TIMESTAMP_FRAC                 = 12
	IOAM6_EVENT_ATTR_DEX_DATA_TRANSIT                        = 13
	IOAM6_EVENT_ATTR_DEX_DATA_NAMESPACE_SPECIFIC             = 14
	IOAM6_EVENT_ATTR_DEX_DATA_QUEUE_DEPTH                    = 15
	IOAM6_EVENT_ATTR_DEX_DATA_CHECKSUM                       = 16
	IOAM6_EVENT_ATTR_DEX_DATA_HOP_LIM_NODE_ID_WIDE           = 17
	IOAM6_EVENT_ATTR_DEX_DATA_INGRESS_EGRESS_INTERFACES_WIDE = 18
	IOAM6_EVENT_ATTR_DEX_DATA_NAMESPACE_SPECIFIC_WIDE        = 19
	IOAM6_EVENT_ATTR_DEX_DATA_BUFFER_OCCUPANCY               = 20
	IOAM6_EVENT_ATTR_DEX_BIT_13                              = 21
	IOAM6_EVENT_ATTR_DEX_BIT_14                              = 22
	IOAM6_EVENT_ATTR_DEX_BIT_15                              = 23
	IOAM6_EVENT_ATTR_DEX_BIT_16                              = 24
	IOAM6_EVENT_ATTR_DEX_BIT_17                              = 25
	IOAM6_EVENT_ATTR_DEX_BIT_18                              = 26
	IOAM6_EVENT_ATTR_DEX_BIT_19                              = 27
	IOAM6_EVENT_ATTR_DEX_BIT_20                              = 28
	IOAM6_EVENT_ATTR_DEX_BIT_21                              = 29
	IOAM6_EVENT_ATTR_DEX_BIT_12                              = 30
	IOAM6_EVENT_ATTR_DEX_OSS_SCID                            = 31
	IOAM6_EVENT_ATTR_DEX_OSS_DATA                            = 32
)

// IOAM-related constants
const (
	IOAM6_TRACE_DATA_SIZE_MAX = 244

	TRACE_TYPE_BIT0_MASK  = 1 << 23
	TRACE_TYPE_BIT1_MASK  = 1 << 22
	TRACE_TYPE_BIT2_MASK  = 1 << 21
	TRACE_TYPE_BIT3_MASK  = 1 << 20
	TRACE_TYPE_BIT4_MASK  = 1 << 19
	TRACE_TYPE_BIT5_MASK  = 1 << 18
	TRACE_TYPE_BIT6_MASK  = 1 << 17
	TRACE_TYPE_BIT7_MASK  = 1 << 16
	TRACE_TYPE_BIT8_MASK  = 1 << 15
	TRACE_TYPE_BIT9_MASK  = 1 << 14
	TRACE_TYPE_BIT10_MASK = 1 << 13
	TRACE_TYPE_BIT22_MASK = 1 << 1
)

var ioamPtoTemplate = IPFIXTemplateRecord{
	TemplateId: TEMPLATE_ID, // Unique Template ID for IOAM Data
	FieldCount: 15,          // Including the Snapshot field, which is variable-length and enterprise-specific
	Fields: []IPFIXFieldSpecifier{
		{FieldId: (0 | 0x8000), FieldLen: 4},      // TraceType (4 bytes)
		{FieldId: (1 | 0x8000), FieldLen: 1},      // HopLimit (1 byte)
		{FieldId: (2 | 0x8000), FieldLen: 3},      // NodeId (24 bits => 3 bytes)
		{FieldId: (3 | 0x8000), FieldLen: 2},      // IngressId (2 bytes)
		{FieldId: (4 | 0x8000), FieldLen: 2},      // EgressId (2 bytes)
		{FieldId: (5 | 0x8000), FieldLen: 4},      // TimestampSecs (4 bytes)
		{FieldId: (6 | 0x8000), FieldLen: 4},      // TimestampFrac (4 bytes)
		{FieldId: (7 | 0x8000), FieldLen: 4},      // NamespaceData (4 bytes)
		{FieldId: (8 | 0x8000), FieldLen: 4},      // QueueDepth (4 bytes)
		{FieldId: (9 | 0x8000), FieldLen: 7},      // IdWide (56 bits => 7 bytes)
		{FieldId: (10 | 0x8000), FieldLen: 4},     // IngressIdWide (4 bytes)
		{FieldId: (11 | 0x8000), FieldLen: 4},     // EgressIdWide (4 bytes)
		{FieldId: (12 | 0x8000), FieldLen: 8},     // NamespaceDataWide (8 bytes)
		{FieldId: (13 | 0x8000), FieldLen: 3},     // NamespaceDataWide (8 bytes)
		{FieldId: (14 | 0x8000), FieldLen: 65535}, // Opaque State Snapshot (variable length)
	},
}

var ioamDexTemplate = IPFIXTemplateRecord{
	TemplateId: TEMPLATE_ID, // Unique Template ID for IOAM Data
	FieldCount: 17,          // Including the Snapshot field, which is variable-length and enterprise-specific
	Fields: []IPFIXFieldSpecifier{
		{FieldId: (0 | 0x8000), FieldLen: 2},      // DEX namespace
		{FieldId: (1 | 0x8000), FieldLen: 4},      // DEX flow id
		{FieldId: (2 | 0x8000), FieldLen: 4},      // DEX seq num
		{FieldId: (3 | 0x8000), FieldLen: 4},      // HopLimit
		{FieldId: (4 | 0x8000), FieldLen: 4},      // NodeId
		{FieldId: (5 | 0x8000), FieldLen: 4},      // IngressId
		{FieldId: (6 | 0x8000), FieldLen: 4},      // EgressId
		{FieldId: (7 | 0x8000), FieldLen: 4},      // TimestampSecs
		{FieldId: (8 | 0x8000), FieldLen: 4},      // TimestampFrac
		{FieldId: (9 | 0x8000), FieldLen: 4},      // NamespaceData
		{FieldId: (10 | 0x8000), FieldLen: 4},     // QueueDepth
		{FieldId: (11 | 0x8000), FieldLen: 8},     // HopLimitWide
		{FieldId: (12 | 0x8000), FieldLen: 8},     // NodeIdWide
		{FieldId: (13 | 0x8000), FieldLen: 8},     // IngressIdWide
		{FieldId: (14 | 0x8000), FieldLen: 8},     // EgressIdWide
		{FieldId: (15 | 0x8000), FieldLen: 8},     // NamespaceDataWide
		{FieldId: (16 | 0x8000), FieldLen: 65535}, // Opaque State Snapshot (variable length)
	},
}
