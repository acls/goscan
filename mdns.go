package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"strings"
	"time"
)

func listenMDNS(ctx context.Context) {
	handle, err := pcap.OpenLive(iface, 1024, false, 10*time.Second)
	if err != nil {
		log.Fatal("pcap failed to open: ", err)
	}
	defer handle.Close()
	handle.SetBPFFilter("udp and port 5353")
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-ps.Packets():
			if len(p.Layers()) == 4 {
				c := p.Layers()[3].LayerContents()
				if c[2] == 0x84 && c[3] == 0x00 && c[6] == 0x00 && c[7] == 0x01 {
					// IP from the network layer (ipv4), do not consider IPv6
					i := p.Layer(layers.LayerTypeIPv4)
					if i == nil {
						continue
					}
					ipv4 := i.(*layers.IPv4)
					ip := ipv4.SrcIP.String()
					// The hostname into the database
					h := ParseMdns(c)
					if len(h) > 0 {
						pushData(ip, nil, h, "")
					}
				}
			}
		}
	}
}

// According to ip generated mdns request packet, the packet is stored in the buffer
func mdns(buffer *Buffer, ip string) {
	b := buffer.PrependBytes(12)
	binary.BigEndian.PutUint16(b, uint16(0))          // 0x0000 logo
	binary.BigEndian.PutUint16(b[2:], uint16(0x0100)) // logo
	binary.BigEndian.PutUint16(b[4:], uint16(1))      // Number of questions
	binary.BigEndian.PutUint16(b[6:], uint16(0))      // Number of resources
	binary.BigEndian.PutUint16(b[8:], uint16(0))      // Authorized resource records
	binary.BigEndian.PutUint16(b[10:], uint16(0))     // Additional resource records
	// Query the problem
	ipList := strings.Split(ip, ".")
	for j := len(ipList) - 1; j >= 0; j-- {
		ip := ipList[j]
		b = buffer.PrependBytes(len(ip) + 1)
		b[0] = uint8(len(ip))
		for i := 0; i < len(ip); i++ {
			b[i+1] = uint8(ip[i])
		}
	}
	b = buffer.PrependBytes(8)
	b[0] = 7 // Subsequent total bytes
	copy(b[1:], []byte{'i', 'n', '-', 'a', 'd', 'd', 'r'})
	b = buffer.PrependBytes(5)
	b[0] = 4 // Subsequent total bytes
	copy(b[1:], []byte{'a', 'r', 'p', 'a'})
	b = buffer.PrependBytes(1)
	// terminator
	b[0] = 0
	// type and classIn
	b = buffer.PrependBytes(4)
	binary.BigEndian.PutUint16(b, uint16(12))
	binary.BigEndian.PutUint16(b[2:], 1)
}

func sendMdns(ip IP, mhaddr net.HardwareAddr) {
	srcIp := net.ParseIP(ipNet.IP.String()).To4()
	dstIp := net.ParseIP(ip.String()).To4()
	ether := &layers.Ethernet{
		SrcMAC:       localHaddr,
		DstMAC:       mhaddr,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip4 := &layers.IPv4{
		Version:  uint8(4),
		IHL:      uint8(5),
		TTL:      uint8(255),
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIp,
		DstIP:    dstIp,
	}
	bf := NewBuffer()
	mdns(bf, ip.String())
	udpPayload := bf.data
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(60666),
		DstPort: layers.UDPPort(5353),
	}
	udp.SetNetworkLayerForChecksum(ip4)
	udp.Payload = udpPayload // todo
	buffer := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true, // Automatically calculate the length
		ComputeChecksums: true, // Automatic calculation of checksum
	}
	err := gopacket.SerializeLayers(buffer, opt, ether, ip4, udp, gopacket.Payload(udpPayload))
	if err != nil {
		log.Fatal("Serialize layers issue: ", err)
	}
	outgoingPacket := buffer.Bytes()

	handle, err := pcap.OpenLive(iface, 1024, false, 10*time.Second)
	if err != nil {
		log.Fatal("pcap failed to open: ", err)
	}
	defer handle.Close()
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal("Failed to send udp packet.. ", err)
	}
}

// Parameter data beginning of the dns protocol header 0x0000 0x8400 0x0000 0x0001 (ans) 0x0000 0x0000
// Obtain the host name from the mdns response packet
func ParseMdns(data []byte) string {
	var buf bytes.Buffer
	i := bytes.Index(data, []byte{0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00})
	if i < 0 {
		return ""
	}

	for s := i - 1; s > 1; s-- {
		num := i - s
		if s-2 < 0 {
			break
		}
		// Includes .local_ 7 characters
		if bto16([]byte{data[s-2], data[s-1]}) == uint16(num+7) {
			return Reverse(buf.String())
		}
		buf.WriteByte(data[s])
	}

	return ""
}

func bto16(b []byte) uint16 {
	if len(b) != 2 {
		log.Fatal("b can only be 2 bytes")
	}
	return uint16(b[0])<<8 + uint16(b[1])
}
