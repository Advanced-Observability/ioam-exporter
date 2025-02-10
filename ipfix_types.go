package main

type IoamNodePTO struct {
	TraceType                   uint32
	HopLimit                    uint8
	NodeId                      uint32 // 24 bits used.
	IngressId, EgressId         uint16
	TimestampSecs               uint32
	TimestampFrac               uint32
	NamespaceData               uint32
	QueueDepth                  uint32
	IdWide                      uint64 // 56 bits used.
	IngressIdWide, EgressIdWide uint32
	NamespaceDataWide           uint64
	OssLen                      uint8
	OssSchema                   uint32 // 24 bits used.
	Snapshot                    []byte
}

type IoamNodeDEX struct {
	Namespace                   uint16
	DexFlowID                   uint32
	DexSeqNum                   uint32
	HopLimit                    uint32
	NodeId                      uint32
	IngressId, EgressId         uint32
	TimestampSecs               uint32
	TimestampFrac               uint32
	NamespaceData               uint32
	QueueDepth                  uint32
	HopLimitWide                uint64
	NodeIdWide                  uint64
	IngressIdWide, EgressIdWide uint64
	NamespaceDataWide           uint64
	OssSchema                   uint32 // 24 bits used.
	Snapshot                    []byte
}

type IPFIXHeader struct {
	Version    uint16
	Length     uint16
	ExportTime uint32
	SeqNumber  uint32
	DomainID   uint32
}

type IPFIXSetHeader struct {
	SetId     uint16
	SetLength uint16
}

type IPFIXFieldSpecifier struct {
	FieldId  uint16
	FieldLen uint16
}

type IPFIXTemplateRecord struct {
	TemplateId uint16
	FieldCount uint16
	Fields     []IPFIXFieldSpecifier
}
