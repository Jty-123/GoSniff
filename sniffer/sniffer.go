package sniffer

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	device      string = "eth0"
	snapshotLen int32  = 1600
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
	Size            string
	Detail          string
	Dump            string
}

type SniffPacket struct {
	// SourceIP       string
	// DestinationIP  string
	// SourceMac      string
	// DestinationMac string
	Time        string
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

func savePcapFile(saveList []gopacket.Packet) {
	// 保存抓取的数据包

	f, err := os.Create("save.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	pcapw := pcapgo.NewWriter(f)
	if err := pcapw.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		log.Fatalf("WriteFileHeader: %v", err)
	} // 添加 pcap 文件头
	for _, packet := range saveList {
		if err := pcapw.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
			log.Fatalf("pcap.WritePacket(): %v", err)
		}
	}

}

func Sniff(name string, ch chan SniffPacket, stop chan int, filter string) {

	var saveList []gopacket.Packet
	recv := make(chan gopacket.Packet)
	stopRecv := make(chan int)
	go recvpacket(name, recv, stopRecv, filter)
	for {
		select {
		case packet := <-recv:
			ch <- parsePacket(packet)
			saveList = append(saveList, packet)
		case signal := <-stop:
			// 0 开始抓包
			// 1 停止抓包
			// 2 保存
			// 3 窗口关闭
			if signal == 0 {
				go recvpacket(name, recv, stopRecv, filter)
			} else if signal == 1 {
				stopRecv <- 1
			} else if signal == 2 {
				savePcapFile(saveList)
			} else if signal == 3 {
				stopRecv <- 1
			}

		}
	}
}

func recvpacket(device string, recv chan gopacket.Packet, stopRecv chan int, filter string) {
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	// pach := make(chan gopacket.Packet)
	defer handle.Close()
	// 检查过滤器语法
	// _, err := handle.CompileBPFFilter(filter)
	handle.SetBPFFilter(filter)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case packet := <-packetSource.Packets():
			//fmt.Println("recv Packet!")
			//fmt.Println(packet)
			if packet != nil {
				recv <- packet
			}
		case <-stopRecv:
			fmt.Println("stop recv packet")
			return
		}
	}

}

func parsePacket(packet gopacket.Packet) SniffPacket {
	var res SniffPacket
	allLayers := packet.Layers()
	// 获取捕获时间
	res.parseTime(packet)
	// 解析数据包的协议
	res.parseProtocol(packet, allLayers)
	//解析目的地和到达地址
	res.parseAddress(packet, allLayers)
	//解析展示详细信息
	res.parseShowInfo(packet, allLayers)
	return res
}

func (s *SniffPacket) parseTime(packet gopacket.Packet) {
	// 获取捕获时间
	s.Time = packet.Metadata().Timestamp.Format("2006-01-02 15:04:05")
}

func (s *SniffPacket) parseProtocol(packet gopacket.Packet, allLayers []gopacket.Layer) {
	str := allLayers[len(allLayers)-1].LayerType().String()
	// 当数据包有Payload时，检查是否为应用层
	if str == "Payload" {
		if checkHttp(packet) {
			s.Protocol = "HTTP"
		} else {
			s.Protocol = allLayers[len(allLayers)-2].LayerType().String()
		}
	} else {
		s.Protocol = str
	}

}

func (s *SniffPacket) parseAddress(packet gopacket.Packet, allLayers []gopacket.Layer) {
	// 解析目的地和到达地址
	for i := 0; i < len(allLayers); i++ {
		switch allLayers[i].LayerType() {
		case layers.LayerTypeEthernet:
			ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
			ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
			s.Source = ethernetPacket.SrcMAC.String()
			s.Destination = ethernetPacket.DstMAC.String()
		case layers.LayerTypeIPv4:
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			ip, _ := ipv4Layer.(*layers.IPv4)
			s.Source = ip.SrcIP.String()
			s.Destination = ip.DstIP.String()
		case layers.LayerTypeIPv6:
			ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
			ip, _ := ipv6Layer.(*layers.IPv6)
			s.Source = ip.SrcIP.String()
			s.Destination = ip.DstIP.String()
			s.Protocol = ip.NextHeader.String()
		}
	}

}

// 待优化
func (s *SniffPacket) parseShowInfo(packet gopacket.Packet, allLayers []gopacket.Layer) {
	for i := len(allLayers) - 1; i >= 0; i-- {
		if allLayers[i].LayerType().String() == "Payload" {
			applicationLayer := packet.ApplicationLayer()
			if applicationLayer != nil {
				if checkHttp(packet) {
					s.Info = GetDetailInfo(packet, "application")
					return
				}
			}
		}
		if allLayers[i].LayerType().String() == "TCP" || allLayers[i].LayerType().String() == "UDP" {
			s.Info = GetDetailInfo(packet, "transport")
			return
		}
		idx := strings.Index(allLayers[i].LayerType().String(), "IP")
		if idx >= 0 {
			s.Info = GetDetailInfo(packet, "network")
			return
		}
	}
	s.Info = GetDetailInfo(packet, "link")
}

func checkHttp(packet gopacket.Packet) bool {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			return true
			// packetData.Info = GetDetailInfo(packet, "application")
		}
	}
	return false
}

func GetDetailInfo(packet gopacket.Packet, layer string) DetailPacketInfo {
	// layer 可选字符串
	// link 数据链路层
	// network 网络层
	// transport 传输层
	// application 应用层
	var detailInfo DetailPacketInfo
	detailInfo.Size = strconv.Itoa(packet.Metadata().CaptureInfo.Length)
	detailInfo.Dump = GetFullPacketData(packet.Dump())
	// fmt.Println(packet.Dump())
	// fmt.Println(l)
	if layer == "link" {
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		detailInfo.SourceMac = ethernetPacket.SrcMAC.String()
		detailInfo.DestinationMac = ethernetPacket.DstMAC.String()
		arpPacket := packet.Layer(layers.LayerTypeARP)
		arp, _ := arpPacket.(*layers.ARP)
		if arp != nil {
			detailInfo.SourceIP = BytesToIPString(arp.SourceProtAddress)
			detailInfo.DestinationIP = BytesToIPString(arp.DstProtAddress)
			detailInfo.Detail += "AddrType:  " + arp.AddrType.String() + "\n"
			detailInfo.Detail += "Protocol:  " + arp.Protocol.String() + "\n"
		}
		// detailInfo.Size = strconv.FormatUint(uint64(ethernetPacket.Length), 10)
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
			//detailInfo.Size = strconv.FormatUint(uint64(ip.Length), 10)
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
			// detailInfo.Size = strconv.FormatUint(uint64(ip.Length), 10)
			// 添加IPv6头相关信息
			detailInfo.Detail += "Type: " + packet.Layers()[len(packet.Layers())-1].LayerType().String() + "\n"
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
			// payloadLength := len(tcp.Payload)
			// tcpHeaderLength := int(tcp.DataOffset) * 4 // DataOffset 表示 TCP 头的长度（单位是 32 位字）
			// // totalLength := payloadLength + tcpHeaderLength
			// detailInfo.Size = strconv.FormatUint(uint64(totalLength), 10)
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
			// detailInfo.Size = "Data Length:  " + strconv.FormatUint(uint64(udp.Length), 10)
			detailInfo.Detail += "Checksum:  " + strconv.FormatUint(uint64(udp.Checksum), 10) + "\n"

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

		applicationLayer := packet.ApplicationLayer()
		// reg := regexp.MustCompile(`(?s)(GET|POST) (.*?) HTTP.*Host: (.*?)\n`)
		payload := string(applicationLayer.Payload())
		detailInfo.Detail += payload
	}
	return detailInfo
}
