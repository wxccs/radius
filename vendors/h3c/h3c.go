// Package h3c implements Vendor-Specific attributes for H3C Technologies
// Co., Limited (SMI Network Management Private Enterprise Code 25506).
//
// H3C RADIUS extension attributes are carried inside the standard
// RFC 2865 §5.26 Vendor-Specific attribute (Type 26) with the Vendor-Id
// set to 25506 - the SMI code H3C Technologies registered in its own
// right. (An older lineage of H3C / 3Com used code 2011; that code is
// now carried exclusively by Huawei - see the huawei sub-package. The
// two are no longer related on the wire.)
//
// The sub-attribute numbers and semantics below follow the H3C
// "AAA/RADIUS Configuration" documentation, table "H3C RADIUS扩展属性"
// (H3C RADIUS Extension Attributes).
package h3c

import (
	"encoding/binary"
	"net"

	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/vendors"
)

// VendorID is H3C Technologies Co., Limited's SMI Network Management
// Private Enterprise Code, as registered with IANA.
const VendorID uint32 = 25506

// H3C VSA sub-type numbers, per the H3C RADIUS Extension Attributes
// table. Sub-types are encoded as the vendor-type byte inside the
// Type 26 VSA.
const (
	// VendorTypeInputPeakRate is the Input-Peak-Rate VSA (4-byte
	// integer, bit/s). Peak rate of upstream user traffic.
	VendorTypeInputPeakRate byte = 1
	// VendorTypeInputAverageRate is the Input-Average-Rate VSA
	// (4-byte integer, bit/s). Average rate of upstream traffic.
	VendorTypeInputAverageRate byte = 2
	// VendorTypeInputBasicRate is the Input-Basic-Rate VSA (4-byte
	// integer, bit/s). Basic rate of upstream traffic.
	VendorTypeInputBasicRate byte = 3
	// VendorTypeOutputPeakRate is the Output-Peak-Rate VSA (4-byte
	// integer, bit/s). Peak rate of downstream traffic.
	VendorTypeOutputPeakRate byte = 4
	// VendorTypeOutputAverageRate is the Output-Average-Rate VSA
	// (4-byte integer, bit/s). Average rate of downstream traffic.
	VendorTypeOutputAverageRate byte = 5
	// VendorTypeOutputBasicRate is the Output-Basic-Rate VSA (4-byte
	// integer, bit/s). Basic rate of downstream traffic.
	VendorTypeOutputBasicRate byte = 6

	// VendorTypeRemanentVolume is the Remanent_Volume VSA (4-byte
	// integer). Remaining total traffic quota for the connection;
	// unit depends on the server type.
	VendorTypeRemanentVolume byte = 15
	// VendorTypeCommand is the Command VSA (4-byte integer). Session
	// control operation: 1 Trigger-Request, 2 Terminate-Request,
	// 3 SetPolicy, 4 Result, 5 PortalClear.
	VendorTypeCommand byte = 20
	// VendorTypeControlIdentifier is the Control_Identifier VSA
	// (4-byte integer). Identifier for retransmitted packets within a
	// session; must be identical across retransmits of the same packet.
	VendorTypeControlIdentifier byte = 24
	// VendorTypeResultCode is the Result_Code VSA (4-byte integer).
	// Result of a Trigger-Request or SetPolicy: 0 success, non-0
	// failure.
	VendorTypeResultCode byte = 25
	// VendorTypeConnectID is the Connect_ID VSA (4-byte integer).
	// Index of the user connection.
	VendorTypeConnectID byte = 26
	// VendorTypeFTPDirectory is the Ftp_Directory VSA (string).
	// Working directory for an FTP user.
	VendorTypeFTPDirectory byte = 28
	// VendorTypeExecPrivilege is the Exec_Privilege VSA (4-byte
	// integer). EXEC user privilege level.
	VendorTypeExecPrivilege byte = 29
	// VendorTypeNASStartupTimestamp is the NAS_Startup_Timestamp VSA
	// (4-byte integer). NAS boot time in seconds since the Unix epoch.
	VendorTypeNASStartupTimestamp byte = 59
	// VendorTypeIPHostAddr is the Ip_Host_Addr VSA (string). User IP
	// and MAC, format "A.B.C.D hh:hh:hh:hh:hh:hh".
	VendorTypeIPHostAddr byte = 60
	// VendorTypeUserNotify is the User_Notify VSA (string).
	// Information the server transparently passes through to the
	// client.
	VendorTypeUserNotify byte = 61
	// VendorTypeUserHeartbeat is the User_HeartBeat VSA (string,
	// 32-byte hash). Pushed after 802.1X authentication success; stored
	// in the device user list to validate 802.1X client handshake
	// packets. Access-Accept and Accounting-Request only.
	VendorTypeUserHeartbeat byte = 62
	// VendorTypeUserGroup is the User_Group VSA (string). User group(s)
	// pushed after SSL VPN authentication; multiple groups are
	// semicolon-separated.
	VendorTypeUserGroup byte = 140
	// VendorTypeSecurityLevel is the Security_Level VSA (4-byte
	// integer). Security level pushed after SSL VPN user
	// authentication.
	VendorTypeSecurityLevel byte = 141
	// VendorTypeInputIntervalOctets is the Input-Interval-Octets VSA
	// (4-byte integer). Byte difference of input between two realtime
	// accounting intervals.
	VendorTypeInputIntervalOctets byte = 201
	// VendorTypeOutputIntervalOctets is the Output-Interval-Octets VSA
	// (4-byte integer). Byte difference of output between two realtime
	// accounting intervals.
	VendorTypeOutputIntervalOctets byte = 202
	// VendorTypeInputIntervalPackets is the Input-Interval-Packets VSA
	// (4-byte integer). Packet count difference of input between two
	// accounting intervals.
	VendorTypeInputIntervalPackets byte = 203
	// VendorTypeOutputIntervalPackets is the Output-Interval-Packets
	// VSA (4-byte integer). Packet count difference of output between
	// two accounting intervals.
	VendorTypeOutputIntervalPackets byte = 204
	// VendorTypeInputIntervalGigawords is the Input-Interval-Gigawords
	// VSA (4-byte integer). Number of 4 GB multiples of the input byte
	// difference between two accounting intervals.
	VendorTypeInputIntervalGigawords byte = 205
	// VendorTypeOutputIntervalGigawords is the
	// Output-Interval-Gigawords VSA (4-byte integer). Number of 4 GB
	// multiples of the output byte difference between two accounting
	// intervals.
	VendorTypeOutputIntervalGigawords byte = 206
	// VendorTypeBackupNASIP is the Backup-NAS-IP VSA (4-byte IPv4
	// address). Backup source IP the NAS uses for RADIUS packets.
	VendorTypeBackupNASIP byte = 207
	// VendorTypeProductID is the Product_ID VSA (string). Product name.
	VendorTypeProductID byte = 255
)

// newIntVSA is an unexported helper that encodes a 4-byte big-endian
// integer value into an H3C VSA of the given sub-type, mirroring the
// RADIUS integer format used by packet.NewInteger.
func newIntVSA(vt byte, n uint32) packet.Attribute {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, n)
	return vendors.NewVSA(VendorID, vt, b)
}

// newStrVSA is an unexported helper that wraps a UTF-8 string into an
// H3C VSA of the given sub-type.
func newStrVSA(vt byte, s string) packet.Attribute {
	return vendors.NewVSA(VendorID, vt, []byte(s))
}

// New constructs an H3C VSA with an explicit vendor-type and value.
// Use this for sub-types that do not have a dedicated constructor.
func New(vendorType byte, value []byte) packet.Attribute {
	return vendors.NewVSA(VendorID, vendorType, value)
}

// NewInputPeakRate constructs an Input-Peak-Rate VSA. rate is the peak
// upstream rate in bit/s.
func NewInputPeakRate(rate uint32) packet.Attribute {
	return newIntVSA(VendorTypeInputPeakRate, rate)
}

// NewInputAverageRate constructs an Input-Average-Rate VSA. rate is the
// average upstream rate in bit/s.
func NewInputAverageRate(rate uint32) packet.Attribute {
	return newIntVSA(VendorTypeInputAverageRate, rate)
}

// NewInputBasicRate constructs an Input-Basic-Rate VSA. rate is the
// basic upstream rate in bit/s.
func NewInputBasicRate(rate uint32) packet.Attribute {
	return newIntVSA(VendorTypeInputBasicRate, rate)
}

// NewOutputPeakRate constructs an Output-Peak-Rate VSA. rate is the
// peak downstream rate in bit/s.
func NewOutputPeakRate(rate uint32) packet.Attribute {
	return newIntVSA(VendorTypeOutputPeakRate, rate)
}

// NewOutputAverageRate constructs an Output-Average-Rate VSA. rate is
// the average downstream rate in bit/s.
func NewOutputAverageRate(rate uint32) packet.Attribute {
	return newIntVSA(VendorTypeOutputAverageRate, rate)
}

// NewOutputBasicRate constructs an Output-Basic-Rate VSA. rate is the
// basic downstream rate in bit/s.
func NewOutputBasicRate(rate uint32) packet.Attribute {
	return newIntVSA(VendorTypeOutputBasicRate, rate)
}

// NewRemanentVolume constructs a Remanent_Volume VSA. vol is the
// remaining traffic quota (unit depends on the server type).
func NewRemanentVolume(vol uint32) packet.Attribute {
	return newIntVSA(VendorTypeRemanentVolume, vol)
}

// NewCommand constructs a Command VSA. op is the session control
// operation (1 Trigger-Request, 2 Terminate-Request, 3 SetPolicy,
// 4 Result, 5 PortalClear).
func NewCommand(op uint32) packet.Attribute {
	return newIntVSA(VendorTypeCommand, op)
}

// NewControlIdentifier constructs a Control_Identifier VSA.
func NewControlIdentifier(id uint32) packet.Attribute {
	return newIntVSA(VendorTypeControlIdentifier, id)
}

// NewResultCode constructs a Result_Code VSA. code is the result (0
// success, non-0 failure) of a Trigger-Request or SetPolicy.
func NewResultCode(code uint32) packet.Attribute {
	return newIntVSA(VendorTypeResultCode, code)
}

// NewConnectID constructs a Connect_ID VSA.
func NewConnectID(id uint32) packet.Attribute {
	return newIntVSA(VendorTypeConnectID, id)
}

// NewFTPDirectory constructs a Ftp_Directory VSA.
func NewFTPDirectory(dir string) packet.Attribute {
	return newStrVSA(VendorTypeFTPDirectory, dir)
}

// NewExecPrivilege constructs an Exec_Privilege VSA. level is the EXEC
// user privilege level.
func NewExecPrivilege(level uint32) packet.Attribute {
	return newIntVSA(VendorTypeExecPrivilege, level)
}

// NewNASStartupTimestamp constructs a NAS_Startup_Timestamp VSA. ts is
// the NAS boot time in seconds since the Unix epoch.
func NewNASStartupTimestamp(ts uint32) packet.Attribute {
	return newIntVSA(VendorTypeNASStartupTimestamp, ts)
}

// NewIPHostAddr constructs an Ip_Host_Addr VSA. addr should be in the
// "A.B.C.D hh:hh:hh:hh:hh:hh" form; it is carried verbatim.
func NewIPHostAddr(addr string) packet.Attribute {
	return newStrVSA(VendorTypeIPHostAddr, addr)
}

// NewUserNotify constructs a User_Notify VSA.
func NewUserNotify(info string) packet.Attribute {
	return newStrVSA(VendorTypeUserNotify, info)
}

// NewUserHeartbeat constructs a User_HeartBeat VSA. hb is the 32-byte
// hash string used to validate 802.1X client handshake packets.
func NewUserHeartbeat(hb []byte) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeUserHeartbeat, append([]byte(nil), hb...))
}

// NewUserGroup constructs a User_Group VSA. groups is the user group
// name; multiple groups are semicolon-separated.
func NewUserGroup(groups string) packet.Attribute {
	return newStrVSA(VendorTypeUserGroup, groups)
}

// NewSecurityLevel constructs a Security_Level VSA. level is the SSL
// VPN security level.
func NewSecurityLevel(level uint32) packet.Attribute {
	return newIntVSA(VendorTypeSecurityLevel, level)
}

// NewInputIntervalOctets constructs an Input-Interval-Octets VSA.
func NewInputIntervalOctets(n uint32) packet.Attribute {
	return newIntVSA(VendorTypeInputIntervalOctets, n)
}

// NewOutputIntervalOctets constructs an Output-Interval-Octets VSA.
func NewOutputIntervalOctets(n uint32) packet.Attribute {
	return newIntVSA(VendorTypeOutputIntervalOctets, n)
}

// NewInputIntervalPackets constructs an Input-Interval-Packets VSA.
func NewInputIntervalPackets(n uint32) packet.Attribute {
	return newIntVSA(VendorTypeInputIntervalPackets, n)
}

// NewOutputIntervalPackets constructs an Output-Interval-Packets VSA.
func NewOutputIntervalPackets(n uint32) packet.Attribute {
	return newIntVSA(VendorTypeOutputIntervalPackets, n)
}

// NewInputIntervalGigawords constructs an Input-Interval-Gigawords VSA.
func NewInputIntervalGigawords(n uint32) packet.Attribute {
	return newIntVSA(VendorTypeInputIntervalGigawords, n)
}

// NewOutputIntervalGigawords constructs an Output-Interval-Gigawords
// VSA.
func NewOutputIntervalGigawords(n uint32) packet.Attribute {
	return newIntVSA(VendorTypeOutputIntervalGigawords, n)
}

// NewBackupNASIP constructs a Backup-NAS-IP VSA. ip is encoded as a
// 4-byte IPv4 address; if ip is not an IPv4 address, 4 zero bytes are
// stored.
func NewBackupNASIP(ip net.IP) packet.Attribute {
	v4 := ip.To4()
	if v4 == nil {
		v4 = make([]byte, 4)
	}
	return vendors.NewVSA(VendorID, VendorTypeBackupNASIP, append([]byte(nil), v4...))
}

// NewProductID constructs a Product_ID VSA.
func NewProductID(id string) packet.Attribute {
	return newStrVSA(VendorTypeProductID, id)
}

// Decode returns the vendor-type and value if attr is an H3C VSA
// (Vendor-Id 25506). Returns ok=false otherwise.
func Decode(attr packet.Attribute) (vendorType byte, value []byte, ok bool) {
	return vendors.MatchVSA(attr, VendorID)
}
