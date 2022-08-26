package wel

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// EventType describes the type of event signalled in the event log.
type EventType uint32

// BIOS Events (TCG PC Client Specific Implementation Specification for Conventional BIOS 1.21)
const (
	PrebootCert          EventType = 0x00000000
	PostCode             EventType = 0x00000001
	unused               EventType = 0x00000002
	NoAction             EventType = 0x00000003
	Separator            EventType = 0x00000004
	Action               EventType = 0x00000005
	EventTag             EventType = 0x00000006
	SCRTMContents        EventType = 0x00000007
	SCRTMVersion         EventType = 0x00000008
	CpuMicrocode         EventType = 0x00000009
	PlatformConfigFlags  EventType = 0x0000000A
	TableOfDevices       EventType = 0x0000000B
	CompactHash          EventType = 0x0000000C
	Ipl                  EventType = 0x0000000D
	IplPartitionData     EventType = 0x0000000E
	NonhostCode          EventType = 0x0000000F
	NonhostConfig        EventType = 0x00000010
	NonhostInfo          EventType = 0x00000011
	OmitBootDeviceEvents EventType = 0x00000012
)

// EFI Events (TCG EFI Platform Specification Version 1.22)
const (
	EFIEventBase               EventType = 0x80000000
	EFIVariableDriverConfig    EventType = 0x80000001
	EFIVariableBoot            EventType = 0x80000002
	EFIBootServicesApplication EventType = 0x80000003
	EFIBootServicesDriver      EventType = 0x80000004
	EFIRuntimeServicesDriver   EventType = 0x80000005
	EFIGPTEvent                EventType = 0x80000006
	EFIAction                  EventType = 0x80000007
	EFIPlatformFirmwareBlob    EventType = 0x80000008
	EFIHandoffTables           EventType = 0x80000009
	EFIHCRTMEvent              EventType = 0x80000010
	EFIVariableAuthority       EventType = 0x800000e0
)

var eventTypeNames = map[EventType]string{
	PrebootCert:          "Preboot Cert",
	PostCode:             "POST Code",
	unused:               "Unused",
	NoAction:             "No Action",
	Separator:            "Separator",
	Action:               "Action",
	EventTag:             "Event Tag",
	SCRTMContents:        "S-CRTM Contents",
	SCRTMVersion:         "S-CRTM Version",
	CpuMicrocode:         "CPU Microcode",
	PlatformConfigFlags:  "Platform Config Flags",
	TableOfDevices:       "Table of Devices",
	CompactHash:          "Compact Hash",
	Ipl:                  "IPL",
	IplPartitionData:     "IPL Partition Data",
	NonhostCode:          "Non-Host Code",
	NonhostConfig:        "Non-HostConfig",
	NonhostInfo:          "Non-Host Info",
	OmitBootDeviceEvents: "Omit Boot Device Events",

	EFIEventBase:               "EFI Event Base",
	EFIVariableDriverConfig:    "EFI Variable Driver Config",
	EFIVariableBoot:            "EFI Variable Boot",
	EFIBootServicesApplication: "EFI Boot Services Application",
	EFIBootServicesDriver:      "EFI Boot Services Driver",
	EFIRuntimeServicesDriver:   "EFI Runtime Services Driver",
	EFIGPTEvent:                "EFI GPT Event",
	EFIAction:                  "EFI Action",
	EFIPlatformFirmwareBlob:    "EFI Platform Firmware Blob",
	EFIVariableAuthority:       "EFI Variable Authority",
	EFIHandoffTables:           "EFI Handoff Tables",
	EFIHCRTMEvent:              "EFI H-CRTM Event",
}

func (e EventType) String() string {
	if s, ok := eventTypeNames[e]; ok {
		return s
	}
	return fmt.Sprintf("EventType(0x%x)", uint32(e))
}

// UntrustedParseEventType returns the event type indicated by
// the provided value.
func UntrustedParseEventType(et uint32) (EventType, error) {
	// "The value associated with a UEFI specific platform event type MUST be in
	// the range between 0x80000000 and 0x800000FF, inclusive."
	if (et < 0x80000000 && et > 0x800000FF) || (et < 0x0 && et > 0x12) {
		return EventType(0), fmt.Errorf("event type not between [0x0, 0x12] or [0x80000000, 0x800000FF]: got %#x", et)
	}
	if _, ok := eventTypeNames[EventType(et)]; !ok {
		return EventType(0), fmt.Errorf("unknown event type %#x", et)
	}
	return EventType(et), nil
}

// ParseTaggedEventData parses a TCG_PCClientTaggedEventStruct structure.
func ParseTaggedEventData(d []byte) (*TaggedEventData, error) {
	var (
		r      = bytes.NewReader(d)
		header struct {
			ID      uint32
			DataLen uint32
		}
	)
	if err := binary.Read(r, binary.LittleEndian, &header); err != nil {
		return nil, fmt.Errorf("reading header: %w", err)
	}

	if int(header.DataLen) > len(d) {
		return nil, fmt.Errorf("tagged event len (%d bytes) larger than data length (%d bytes)", header.DataLen, len(d))
	}

	out := TaggedEventData{
		ID:   header.ID,
		Data: make([]byte, header.DataLen),
	}
	return &out, binary.Read(r, binary.LittleEndian, &out.Data)
}
