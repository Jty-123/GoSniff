package sniffer

import (
	"log"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device      string = "eth0"
	snapshotLen int32  = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = 1 * time.Second
	handle      *pcap.Handle
)

var DecodedPacketChannel chan string

type SniffPacket struct {
	// SourceIP       string
	// DestinationIP  string
	// SourceMac      string
	// DestinationMac string
	Source       string
	Destionation string
	Protocol     string
	Length       int
	info         string
}

func GetAllDeviceName() []string {
	// 得到所有的(网络)设备
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	var deviceNames = []string{}

	for _, device := range devices {
		deviceNames = append(deviceNames, device.Name)
	}
	return deviceNames
}

func Sniff(name string, ch chan SniffPacket) {
	device = name
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	// pach := make(chan gopacket.Packet)
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ch <- DecodePacket(packet)
	}
}

func DecodePacket(packet gopacket.Packet) SniffPacket {

	var packetData SniffPacket
	// Let's see if the packet is an ethernet packet
	linkLayer := packet.LinkLayer()
	if linkLayer != nil {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil {
			ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
			packetData.Source = ethernetPacket.SrcMAC.String()
			packetData.Destionation = ethernetPacket.DstMAC.String()
			packetData.Protocol = linkLayer.LayerType().String()
			networkLayer := packet.NetworkLayer()
			if networkLayer != nil {
				ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
				if ipv4Layer != nil {
					ip, _ := ipv4Layer.(*layers.IPv4)
					packetData.Source = ip.SrcIP.String()
					packetData.Destionation = ip.DstIP.String()
					packetData.Protocol = ip.Protocol.String()
				}
				ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
				if ipv6Layer != nil {
					ip, _ := ipv6Layer.(*layers.IPv6)
					packetData.Source = ip.SrcIP.String()
					packetData.Destionation = ip.DstIP.String()
					packetData.Protocol = ip.NextHeader.String()
				}
				applicationLayer := packet.ApplicationLayer()
				if applicationLayer != nil {
					if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
						packetData.Protocol = "HTTP"
					}
					// to do
					return packetData
					// fmt.Println(packetData.Source, " ", packetData.Destionation, " ", packetData.Protocol)
				} else {
					return packetData
					// fmt.Println(packetData.Source, " ", packetData.Destionation, " ", packetData.Protocol)
				}
			} else {
				return packetData
				// fmt.Println(packetData.Source, " ", packetData.Destionation, " ", packetData.Protocol)
			}
		}
	}
	return packetData
}
