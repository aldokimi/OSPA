package policy

// CheckFieldKind describes how a check condition should be edited in the UI.
type CheckFieldKind string

const (
	CheckFieldBool    CheckFieldKind = "bool"
	CheckFieldBoolOpt CheckFieldKind = "bool_opt" // true / false / unset
	CheckFieldInt     CheckFieldKind = "int"
	CheckFieldString  CheckFieldKind = "string"
	CheckFieldList    CheckFieldKind = "list"
)

// CheckFieldMeta describes one editable check field.
type CheckFieldMeta struct {
	Name        string
	Kind        CheckFieldKind
	Label       string
	Placeholder string
	Help        string
}

// CheckField returns UI metadata for a check condition name.
func CheckField(name string) CheckFieldMeta {
	meta := CheckFieldMeta{
		Name:  name,
		Kind:  CheckFieldString,
		Label: name,
	}
	switch name {
	case "unused", "unassociated", "port_range_wide", "shared_network",
		"no_security_group", "no_keypair", "password_expired",
		"has_admin_role", "admin_via_group":
		meta.Kind = CheckFieldBool
		meta.Help = "Match when this condition is true"
	case "is_public", "encrypted", "attached", "has_backup", "quota_set",
		"public_write", "mfa_enabled", "tls_disabled", "console_enabled",
		"has_tls_container":
		meta.Kind = CheckFieldBoolOpt
		meta.Help = "Match resources where the value equals your choice"
	case "port":
		meta.Kind = CheckFieldInt
		meta.Placeholder = "22"
	case "exempt_names", "image_name", "qos_spec_keys":
		meta.Kind = CheckFieldList
		meta.Placeholder = "comma,separated,values"
	case "age_gt":
		meta.Placeholder = "30d"
		meta.Help = "Duration threshold (e.g. 7d, 24h)"
	case "status":
		meta.Placeholder = "ACTIVE / ERROR / DOWN"
	case "direction":
		meta.Placeholder = "ingress / egress"
	case "ethertype":
		meta.Placeholder = "IPv4 / IPv6"
	case "protocol":
		meta.Placeholder = "tcp / udp / icmp / HTTP"
	case "remote_ip_prefix":
		meta.Placeholder = "0.0.0.0/0"
	case "visibility":
		meta.Placeholder = "public / private / shared"
	case "secret_type":
		meta.Placeholder = "passphrase / certificate / opaque"
	case "secret_risk":
		meta.Placeholder = "high / medium / low"
	case "record_type":
		meta.Placeholder = "A / AAAA / MX"
	case "tls_ciphers":
		meta.Placeholder = "OpenSSL cipher list"
	case "network_driver":
		meta.Placeholder = "flannel / calico"
	case "boot_interface":
		meta.Placeholder = "pxe / ipxe"
	case "qos_consumer":
		meta.Placeholder = "front-end / back-end / both"
	case "token_provider":
		meta.Placeholder = "fernet / uuid"
	}
	return meta
}

// CheckFieldsFor returns UI field metadata for the given check names.
func CheckFieldsFor(names []string) []CheckFieldMeta {
	out := make([]CheckFieldMeta, 0, len(names))
	for _, name := range names {
		if name == "exempt_metadata" {
			// Complex nested match — skip in visual form for now.
			continue
		}
		out = append(out, CheckField(name))
	}
	return out
}
