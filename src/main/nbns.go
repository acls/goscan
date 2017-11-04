package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"math/rand"
	"net"
	"time"
)

func listenNBNS(ctx context.Context) {
	handle, err := pcap.OpenLive(iface, 1024, false, 10*time.Second)
	if err != nil {
		log.Fatal("pcap using failed:", err)
	}
	defer handle.Close()
	handle.SetBPFFilter("udp and port 137 and dst host " + ipNet.IP.String())
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-ps.Packets():
			if len(p.Layers()) == 4 {
				c := p.Layers()[3].LayerContents()
				if len(c) > 8 && c[2] == 0x84 && c[3] == 0x00 && c[6] == 0x00 && c[7] == 0x01 {
					// IP from the network layer (ipv4), do not consider IPv6
					i := p.Layer(layers.LayerTypeIPv4)
					if i == nil {
						continue
					}
					ipv4 := i.(*layers.IPv4)
					ip := ipv4.SrcIP.String()
					// The hostname into the database
					m := ParseNBNS(c)
					if len(m) > 0 {
						pushData(ip, nil, m, "")
					}
				}
			}
		}
	}
}

// According to ip generated mdns request packet, the packet is stored in the buffer
func nbns(buffer *Buffer) {
	rand.Seed(time.Now().UnixNano())
	tid := rand.Intn(0x7fff)
	b := buffer.PrependBytes(12)
	binary.BigEndian.PutUint16(b, uint16(tid))        // 0x0000 logo
	binary.BigEndian.PutUint16(b[2:], uint16(0x0010)) // logo
	binary.BigEndian.PutUint16(b[4:], uint16(1))      // Number of questions
	binary.BigEndian.PutUint16(b[6:], uint16(0))      // Number of resources
	binary.BigEndian.PutUint16(b[8:], uint16(0))      // Authorized resource records
	binary.BigEndian.PutUint16(b[10:], uint16(0))     // Additional resource records
	// Query the problem
	b = buffer.PrependBytes(1)
	b[0] = 0x20
	b = buffer.PrependBytes(32)
	copy(b, []byte{0x43, 0x4b})
	for i := 2; i < 32; i++ {
		b[i] = 0x41
	}

	b = buffer.PrependBytes(1)
	// terminator
	b[0] = 0
	// type and classIn
	b = buffer.PrependBytes(4)
	binary.BigEndian.PutUint16(b, uint16(33))
	binary.BigEndian.PutUint16(b[2:], 1)
}

func sendNbns(ip IP, mhaddr net.HardwareAddr) {
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
	nbns(bf)
	udpPayload := bf.data
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(61666),
		DstPort: layers.UDPPort(137),
	}
	udp.SetNetworkLayerForChecksum(ip4)
	udp.Payload = udpPayload
	buffer := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true, // Automatically calculate the length
		ComputeChecksums: true, // Automatic calculation of checksum
	}
	err := gopacket.SerializeLayers(buffer, opt, ether, ip4, udp, gopacket.Payload(udpPayload))
	if err != nil {
		log.Fatal("Serialize layers出现问题:", err)
	}
	outgoingPacket := buffer.Bytes()

	handle, err := pcap.OpenLive(iface, 1024, false, 10*time.Second)
	if err != nil {
		log.Fatal("pcap打开失败:", err)
	}
	defer handle.Close()
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal("Failed to send udp packet..")
	}
}

func ParseNBNS(data []byte) string {
	var buf bytes.Buffer
	i := bytes.Index(data, []byte{0x20, 0x43, 0x4b, 0x41, 0x41})
	if i < 0 || len(data) < 32 {
		return ""
	}
	index := i + 1 + 0x20 + 12
	// data [index-1] is on the index of number of names, exit if number of names is 0
	if data[index-1] == 0x00 {
		return ""
	}
	for t := index; ; t++ {
		// 0x20 and 0x00 are terminators
		if data[t] == 0x20 || data[t] == 0x00 {
			break
		}
		buf.WriteByte(data[t])
	}
	return buf.String()
}
