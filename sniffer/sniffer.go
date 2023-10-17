package sniffer

import (
	"fmt"
	"log"
	"strconv"
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

type DetailPacketInfo struct {
	SourceMac       string
	SourceIP        string
	DestinationMac  string
	DestinationIP   string
	SourcePort      string
	DestinationPort string
	DataLen         string
	Detail          string
}

type SniffPacket struct {
	// SourceIP       string
	// DestinationIP  string
	// SourceMac      string
	// DestinationMac string
	Source      string
	Destination string
	Protocol    string
	Info        DetailPacketInfo
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

func Sniff(name string, ch chan SniffPacket, stop chan bool) {
	device = name
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	// pach := make(chan gopacket.Packet)
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case packet := <-packetSource.Packets():
			ch <- DecodePacket(packet)
		case <-stop:
			return
		}
	}
}

func DecodePacket(packet gopacket.Packet) SniffPacket {

	// 逐层解析 数据链路层->应用层
	var packetData SniffPacket
	// Let's see if the packet is an ethernet packet
	linkLayer := packet.LinkLayer()
	if linkLayer != nil {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil {
			ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
			packetData.Source = ethernetPacket.SrcMAC.String()
			packetData.Destination = ethernetPacket.DstMAC.String()
			packetData.Protocol = linkLayer.LayerType().String()
			// ARP协议
			arpPacket := packet.Layer(layers.LayerTypeARP)
			arp, _ := arpPacket.(*layers.ARP)
			if arp != nil {
				fmt.Println("ARP")
				packetData.Protocol = "ARP"
			}
			packetData.Info = GetDetailInfo(packet, "link")
			networkLayer := packet.NetworkLayer()
			if networkLayer != nil {
				ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
				if ipv4Layer != nil {
					ip, _ := ipv4Layer.(*layers.IPv4)
					packetData.Source = ip.SrcIP.String()
					packetData.Destination = ip.DstIP.String()
					packetData.Protocol = ip.Protocol.String()
					// fmt.Println("ip.Protocol:", ip.Protocol.String())
				}
				ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
				if ipv6Layer != nil {
					ip, _ := ipv6Layer.(*layers.IPv6)
					packetData.Source = ip.SrcIP.String()
					packetData.Destination = ip.DstIP.String()
					packetData.Protocol = ip.NextHeader.String()
				}
				packetData.Info = GetDetailInfo(packet, "network")
				transportLayer := packet.TransportLayer()
				if transportLayer != nil {
					packetData.Info = GetDetailInfo(packet, "transport")
				}
				applicationLayer := packet.ApplicationLayer()
				if applicationLayer != nil {
					// packetData.Info = GetDetailInfo(packet, "application")
					if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
						packetData.Protocol = "HTTP"
						packetData.Info = GetDetailInfo(packet, "application")
					}
					// to do
					return packetData
					// fmt.Println(packetData.Source, " ", packetData.Destination, " ", packetData.Protocol)
				} else {
					return packetData
					// fmt.Println(packetData.Source, " ", packetData.Destination, " ", packetData.Protocol)
				}
			} else {
				return packetData
				// fmt.Println(packetData.Source, " ", packetData.Destination, " ", packetData.Protocol)
			}
		}
	}
	return packetData
}

func GetDetailInfo(packet gopacket.Packet, layer string) DetailPacketInfo {
	// layer 可选字符串
	// link 数据链路层
	// network 网络层
	// transport 传输层
	// application 应用层
	var detailInfo DetailPacketInfo
	if layer == "link" {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		detailInfo.SourceMac = ethernetPacket.SrcMAC.String()
		detailInfo.DestinationMac = ethernetPacket.DstMAC.String()
		detailInfo.DataLen = strconv.FormatUint(uint64(ethernetPacket.Length), 10)
		return detailInfo
	}
	if layer == "network" {
		linkLayer := packet.LinkLayer()
		flow := linkLayer.LinkFlow()
		detailInfo.SourceMac = flow.Src().String()
		detailInfo.DestinationMac = flow.Dst().String()
		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
		if ipv4Layer != nil {
			ip, _ := ipv4Layer.(*layers.IPv4)
			detailInfo.SourceIP = ip.SrcIP.String()
			detailInfo.DestinationIP = ip.DstIP.String()
			// 添加IP头相关信息
			detailInfo.DataLen = strconv.FormatUint(uint64(ip.Length), 10)
			detailInfo.Detail += "IHL:  " + strconv.FormatUint(uint64(ip.IHL), 10) + "\n"
			detailInfo.Detail += "TOS:  " + strconv.FormatUint(uint64(ip.TOS), 10) + "\n"
			// fmt.Println(ip.TOS)
			detailInfo.Detail += "Id:  " + strconv.FormatUint(uint64(ip.Id), 10) + "\n"
			// fmt.Println(ip.Id)
			detailInfo.Detail += "Flags:  " + ip.Flags.String() + "\n"
			detailInfo.Detail += "FragOffset:  " + strconv.FormatUint(uint64(ip.FragOffset), 10) + "\n"
			detailInfo.Detail += "TTL:  " + strconv.FormatUint(uint64(ip.TTL), 10) + "\n"
			detailInfo.Detail += "Checksum:  " + strconv.FormatUint(uint64(ip.Checksum), 10) + "\n"
			// fmt.Println(detailInfo.Detail)
		}
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ipv6Layer != nil {
			ip, _ := ipv6Layer.(*layers.IPv6)
			detailInfo.SourceIP = ip.SrcIP.String()
			detailInfo.DestinationIP = ip.DstIP.String()
			detailInfo.DataLen = strconv.FormatUint(uint64(ip.Length), 10)
			// 添加IPv6头相关信息
			detailInfo.Detail += "TrafficClass: " + strconv.FormatUint(uint64(ip.TrafficClass), 10) + "\n"
			detailInfo.Detail += "FlowLabel: " + strconv.FormatUint(uint64(ip.FlowLabel), 10) + "\n"
			detailInfo.Detail += "HopLimit: " + strconv.FormatUint(uint64(ip.Length), 10) + "\n"
		}
		return detailInfo
	}
	if layer == "transport" {
		networkLayer := packet.NetworkLayer()
		linkLayer := packet.LinkLayer()
		netflow := networkLayer.NetworkFlow()
		linkflow := linkLayer.LinkFlow()
		detailInfo.SourceMac = linkflow.Src().String()
		detailInfo.DestinationMac = linkflow.Dst().String()
		detailInfo.SourceIP = netflow.Src().String()
		detailInfo.DestinationIP = netflow.Dst().String()
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			detailInfo.SourcePort = tcp.SrcPort.String()
			detailInfo.DestinationPort = tcp.DstPort.String()
			payloadLength := len(tcp.Payload)
			tcpHeaderLength := int(tcp.DataOffset) * 4 // DataOffset 表示 TCP 头的长度（单位是 32 位字）
			totalLength := payloadLength + tcpHeaderLength
			detailInfo.DataLen = strconv.FormatUint(uint64(totalLength), 10) + "\n"
			detailInfo.Detail += "sequence:  " + strconv.FormatUint(uint64(tcp.Seq), 10) + "\n"
			detailInfo.Detail += "ACK:  " + strconv.FormatUint(uint64(tcp.Ack), 10) + "\n"
			detailInfo.Detail += "Data Offset:  " + strconv.FormatUint(uint64(tcp.DataOffset), 10) + "\n"
			flags := map[string]bool{
				"FIN": tcp.FIN,
				"SYN": tcp.SYN,
				"RST": tcp.RST,
				"PSH": tcp.PSH,
				"ACK": tcp.ACK,
				"URG": tcp.URG,
				"ECE": tcp.ECE,
				"CWR": tcp.CWR,
				"NS":  tcp.NS,
			}
			for k, v := range flags {
				flag := "0"
				if v {
					flag = "1"
				}
				detailInfo.Detail += fmt.Sprintf("%s:  %s ", k, flag)
			}
			detailInfo.Detail += "\n"
			detailInfo.Detail += "window size:  " + strconv.FormatUint(uint64(tcp.Window), 10) + "\n"
			detailInfo.Detail += "checksum:  " + strconv.FormatUint(uint64(tcp.Checksum), 10) + "\n"
			detailInfo.Detail += "urgent pointer:  " + strconv.FormatUint(uint64(tcp.Urgent), 10) + "\n"
		}
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			detailInfo.SourcePort = udp.DstPort.String()
			detailInfo.DestinationPort = udp.DstPort.String()
			detailInfo.DataLen = "Data Length:  " + strconv.FormatUint(uint64(udp.Length), 10)
			detailInfo.Detail += "Checksum:  " + strconv.FormatUint(uint64(udp.Checksum), 10) + "\n"
			detailInfo.Detail += "Payload:  " + string(udp.Payload) + "\n"
			// fmt.Println(string(udp.Payload))
		}
		return detailInfo
	}
	if layer == "application" {
		networkLayer := packet.NetworkLayer()
		linkLayer := packet.LinkLayer()
		netflow := networkLayer.NetworkFlow()
		linkflow := linkLayer.LinkFlow()
		detailInfo.SourceMac = linkflow.Src().String()
		detailInfo.DestinationMac = linkflow.Dst().String()
		detailInfo.SourceIP = netflow.Src().String()
		detailInfo.DestinationIP = netflow.Dst().String()
		// tcpLayer := packet.Layer(layers.LayerTypeTCP)
		// tcp, _ := tcpLayer.(*layers.TCP)
		// detailInfo.SourcePort = tcp.SrcPort.String()
		// detailInfo.DestinationPort = tcp.DstPort.String()

		applicationLayer := packet.ApplicationLayer()
		// reg := regexp.MustCompile(`(?s)(GET|POST) (.*?) HTTP.*Host: (.*?)\n`)
		payload := string(applicationLayer.Payload())
		detailInfo.Detail += payload
		fmt.Println(payload)
		// result := reg.FindStringSubmatch(payload)
		// if len(result) == 4 {
		// 	strings.TrimSpace(result[2])
		// 	url := "http://" + strings.TrimSpace(result[3]) + strings.TrimSpace(result[2])
		// 	detailInfo.Detail += "url:  " + url + "\n"
		// 	detailInfo.Detail += "host:  " + result[3] + "\n"
		// 	// fmt.Println("url:", url)
		// 	// fmt.Println("host:", result[3])
		// }
	}
	return detailInfo
}
