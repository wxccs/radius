// Package juniper implements Vendor-Specific attributes for Juniper
// Networks (SMI Network Management Private Enterprise Code 2636).
//
// Juniper VSAs use the standard RFC 2865 §5.26 layout. The sub-attribute
// numbers and semantics below follow the Junos OS "User Access" RADIUS
// authentication documentation, which lists the Juniper VSAs accepted
// by JUNOS-branded access devices (Vendor-Id 2636). That document
// defines sub-types 1-5 and 8-14; sub-types 6 and 7 are not specified.
package juniper

import (
	"encoding/binary"

	"github.com/wxccs/radius/v2/packet"
	"github.com/wxccs/radius/v2/vendors"
)

// VendorID is Juniper Networks' SMI Network Management Private
// Enterprise Code, as registered with IANA.
const VendorID uint32 = 2636

// Juniper VSA sub-type numbers, per the Junos OS "User Access" RADIUS
// authentication documentation (Table: Juniper Networks Vendor-Specific
// RADIUS Attributes).
const (
	// VendorTypeLocalUserName is the Juniper-Local-User-Name VSA
	// (UTF-8 string). Names the user template account assigned to the
	// authenticated user when the user logs in. Access-Accept only.
	VendorTypeLocalUserName byte = 1
	// VendorTypeAllowCommand is the Juniper-Allow-Commands VSA. Carries
	// an extended POSIX 1003.2 regular expression that grants the user
	// the ability to run operational-mode commands in addition to those
	// authorized by the login-class permission bits. Access-Accept only.
	VendorTypeAllowCommand byte = 2
	// VendorTypeDenyCommand is the Juniper-Deny-Commands VSA. Carries
	// an extended POSIX 1003.2 regular expression that denies the user
	// the ability to run operational-mode commands that the login-class
	// permission bits would otherwise authorize. Access-Accept only.
	VendorTypeDenyCommand byte = 3
	// VendorTypeAllowConfiguration is the Juniper-Allow-Configuration
	// VSA. Carries an extended POSIX 1003.2 regular expression that
	// grants the user the ability to view and modify configuration
	// statements beyond the login-class permission bits.
	// Access-Accept only.
	VendorTypeAllowConfiguration byte = 4
	// VendorTypeDenyConfiguration is the Juniper-Deny-Configuration
	// VSA. Carries an extended POSIX 1003.2 regular expression that
	// denies the user the ability to view or modify configuration
	// statements that the login-class permission bits would otherwise
	// authorize. Access-Accept only.
	VendorTypeDenyConfiguration byte = 5
	// VendorTypeInteractiveCommand is the Juniper-Interactive-Command
	// VSA (UTF-8 string). Carries the interactive command entered by
	// the user. Accounting-Request only.
	VendorTypeInteractiveCommand byte = 8
	// VendorTypeConfigurationChange is the Juniper-Configuration-Change
	// VSA (UTF-8 string). Carries the interactive command that resulted
	// in a configuration (database) change. Accounting-Request only.
	VendorTypeConfigurationChange byte = 9
	// VendorTypeUserPermissions is the Juniper-User-Permissions VSA
	// (UTF-8 string). A space-separated list of permission flags (e.g.
	// "interface interface-control configure") granting the user's
	// access privileges. Access-Accept only.
	VendorTypeUserPermissions byte = 10
	// VendorTypeAuthenticationType is the Juniper-Authentication-Type
	// VSA (UTF-8 string). Indicates the authentication method used:
	// AuthenticationTypeLocal for the local database,
	// AuthenticationTypeRemote for a RADIUS/LDAP server.
	VendorTypeAuthenticationType byte = 11
	// VendorTypeSessionPort is the Juniper-Session-Port VSA (4-byte
	// big-endian integer). Carries the source port number of the
	// established session.
	VendorTypeSessionPort byte = 12
	// VendorTypeAllowConfigurationRegexps is the
	// Juniper-Allow-Configuration-Regexps VSA. Carries an extended
	// POSIX 1003.2 regular expression; the RADIUS-only counterpart of
	// Juniper-Allow-Configuration. Access-Accept only.
	VendorTypeAllowConfigurationRegexps byte = 13
	// VendorTypeDenyConfigurationRegexps is the
	// Juniper-Deny-Configuration-Regexps VSA. Carries an extended
	// POSIX 1003.2 regular expression; the RADIUS-only counterpart of
	// Juniper-Deny-Configuration. Access-Accept only.
	VendorTypeDenyConfigurationRegexps byte = 14
)

// Values carried by the Juniper-Authentication-Type VSA
// (VendorTypeAuthenticationType).
const (
	// AuthenticationTypeLocal indicates the user was authenticated by
	// the local database.
	AuthenticationTypeLocal = "local"
	// AuthenticationTypeRemote indicates the user was authenticated by
	// a RADIUS or LDAP server.
	AuthenticationTypeRemote = "remote"
)

// New constructs a Juniper VSA with an explicit vendor-type and value.
func New(vendorType byte, value []byte) packet.Attribute {
	return vendors.NewVSA(VendorID, vendorType, value)
}

// NewLocalUserName constructs a Juniper-Local-User-Name VSA naming the
// user template account assigned to the authenticated user.
func NewLocalUserName(name string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeLocalUserName, []byte(name))
}

// NewAllowCommand constructs a Juniper-Allow-Commands VSA. expr is an
// extended POSIX 1003.2 regular expression; it is carried verbatim and
// not validated.
func NewAllowCommand(expr string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeAllowCommand, []byte(expr))
}

// NewDenyCommand constructs a Juniper-Deny-Commands VSA. expr is an
// extended POSIX 1003.2 regular expression carried verbatim.
func NewDenyCommand(expr string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeDenyCommand, []byte(expr))
}

// NewAllowConfiguration constructs a Juniper-Allow-Configuration VSA.
// expr is an extended POSIX 1003.2 regular expression carried verbatim.
func NewAllowConfiguration(expr string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeAllowConfiguration, []byte(expr))
}

// NewDenyConfiguration constructs a Juniper-Deny-Configuration VSA.
// expr is an extended POSIX 1003.2 regular expression carried verbatim.
func NewDenyConfiguration(expr string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeDenyConfiguration, []byte(expr))
}

// NewInteractiveCommand constructs a Juniper-Interactive-Command VSA,
// used in Accounting-Request packets to record the command the user
// entered.
func NewInteractiveCommand(cmd string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeInteractiveCommand, []byte(cmd))
}

// NewConfigurationChange constructs a Juniper-Configuration-Change VSA,
// used in Accounting-Request packets to record the command that
// resulted in a configuration change.
func NewConfigurationChange(cmd string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeConfigurationChange, []byte(cmd))
}

// NewUserPermissions constructs a Juniper-User-Permissions VSA. flags
// is a space-separated list of permission flag names (e.g.
// "interface interface-control configure").
func NewUserPermissions(flags string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeUserPermissions, []byte(flags))
}

// NewAuthenticationType constructs a Juniper-Authentication-Type VSA.
// method should be AuthenticationTypeLocal or AuthenticationTypeRemote;
// it is carried verbatim and not validated.
func NewAuthenticationType(method string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeAuthenticationType, []byte(method))
}

// NewSessionPort constructs a Juniper-Session-Port VSA encoding the
// source port as a 4-byte big-endian integer (RADIUS integer format).
func NewSessionPort(port uint32) packet.Attribute {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, port)
	return vendors.NewVSA(VendorID, VendorTypeSessionPort, b)
}

// NewAllowConfigurationRegexps constructs a
// Juniper-Allow-Configuration-Regexps VSA. expr is an extended POSIX
// 1003.2 regular expression carried verbatim.
func NewAllowConfigurationRegexps(expr string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeAllowConfigurationRegexps, []byte(expr))
}

// NewDenyConfigurationRegexps constructs a
// Juniper-Deny-Configuration-Regexps VSA. expr is an extended POSIX
// 1003.2 regular expression carried verbatim.
func NewDenyConfigurationRegexps(expr string) packet.Attribute {
	return vendors.NewVSA(VendorID, VendorTypeDenyConfigurationRegexps, []byte(expr))
}

// Decode returns the vendor-type and value if attr is a Juniper VSA.
// Returns ok=false if attr is not a Juniper VSA.
func Decode(attr packet.Attribute) (vendorType byte, value []byte, ok bool) {
	return vendors.MatchVSA(attr, VendorID)
}
