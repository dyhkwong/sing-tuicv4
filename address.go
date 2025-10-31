package tuicv4

import M "github.com/sagernet/sing/common/metadata"

var AddressSerializer = M.NewSerializer(
	M.AddressFamilyByte(0x00, M.AddressFamilyFqdn),
	M.AddressFamilyByte(0x01, M.AddressFamilyIPv4),
	M.AddressFamilyByte(0x02, M.AddressFamilyIPv6),
)
