package main

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// Define the interface to use
	interfaceName := "eth0"

	// Open the interface for capturing and sending packets
	handle, err := pcap.OpenLive(interfaceName, 65535, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// Prepare the ARP packet
	srcMAC, err := net.ParseMAC("00:11:22:33:44:55")
	if err != nil {
		panic(err)
	}
	srcIP := net.ParseIP("192.168.1.100")
	dstMAC, err := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	if err != nil {
		panic(err)
	}
	dstIP := net.ParseIP("192.168.1.1")

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIP.To4(),
		DstHwAddress:      dstMAC,
		DstProtAddress:    dstIP.To4(),
	}

	// Serialize the packet and send it
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err = gopacket.SerializeLayers(buffer, opts, &arp)
	if err != nil {
		panic(err)
	}
	err = handle.WritePacketData(buffer.Bytes())
	if err != nil {
		panic(err)
	}

	fmt.Println("ARP packet sent successfully")
}
