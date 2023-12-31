package main

import (
	"GoSniff/front"
	"GoSniff/sniffer"
	"fmt"
	"log"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

func CreateNewListenWindow(myApp fyne.App, listenChannel chan sniffer.SniffPacket, stopChannel chan int) {

	var packetData = []string{}
	var packDetailData = []sniffer.SniffPacket{}
	listData := binding.BindStringList(&packetData)
	// listData.Set(packetData)
	list := widget.NewListWithData(listData,
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(i binding.DataItem, o fyne.CanvasObject) {
			o.(*widget.Label).Bind(i.(binding.String))
			o.(*widget.Label).TextStyle = fyne.TextStyle{Monospace: true, Bold: true}
			// o.(*widget.Label).Alignment = fyne.TextAlignLeading
			// o.(*widget.Label).Resize(fyne.NewSize(1000, o.MinSize().Height))
		})

	list.OnSelected = func(id widget.ListItemID) {
		if id == 0 {
			list.Unselect(id)
			return
		}
		packet := packDetailData[id-1]
		info := packet.Info
		var showInfo string
		showInfo += "Protocol: " + packet.Protocol + "\n"
		showInfo += "Source MAC address: " + info.SourceMac + "\n"
		showInfo += "Destination MAC address: " + info.DestinationMac + "\n"
		if info.SourceIP != "" && info.DestinationIP != "" {
			showInfo += "Source IP address: " + info.SourceIP + "\n"
			showInfo += "Destination IP address: " + info.DestinationIP + "\n"
		}
		if info.SourcePort != "" && info.DestinationPort != "" {
			showInfo += "Source Port: " + info.SourcePort + "\n"
			showInfo += "Destination Port: " + info.DestinationPort + "\n"
		}
		showInfo += "Data length:  " + info.Size + " Bytes \n"
		showInfo += "Details:  \n" + info.Detail
		detailWindow := front.CreateDetailWindow(myApp, showInfo, info.Dump)
		detailWindow.Show()
		detailWindow.SetOnClosed(func() {
			list.Unselect(id)
		})
	}
	isStop := false // 是否停止
	// 创建一个顶层容器，将滚动容器放入其中
	MaxList := container.NewStack(list)
	var Button *widget.Button // 停止/开始按钮
	// 停止抓包
	Button = widget.NewButton("Stop", func() {
		if Button.Text == "Stop" {
			Button.SetText("Start")
			stopChannel <- 1
			isStop = true
			log.Println("Stop Listen!")
		} else {
			Button.SetText("Stop")
			stopChannel <- 0
			isStop = false
			log.Println("Start Listen!")
		}
	})
	SaveButton := widget.NewButton("Save", func() {
		if !isStop {
			front.CreateTips(myApp, 1)
			return
		}
		stopChannel <- 2
		log.Println("Saved!")
	})
	bottom := container.NewGridWithColumns(2, Button, SaveButton)
	container := container.NewBorder(nil, bottom, nil, nil, MaxList)
	listenWindow := myApp.NewWindow("Listening")
	listenWindow.SetOnClosed(func() {
		stopChannel <- 3
	})
	listenWindow.SetContent(container)
	listenWindow.Resize(fyne.NewSize(1100, 600))
	listenWindow.Show()
	str := fmt.Sprintf("%-5s%-30s%-40s%-40s%-10s", "No.", "Time", "Source", "Destination", "Protocol")
	listData.Append(str)
	for packet := range listenChannel {
		No := len(packDetailData) + 1
		packDetailData = append(packDetailData, packet)
		str := fmt.Sprintf("%-5d%-30s%-40s%-40s%-10s", No, packet.Time, packet.Source, packet.Destination, packet.Protocol)
		// str := "Time\t\t" + packet.Source + "\t\t" + packet.Destination + "\t\t" + packet.Protocol
		// fmt.Println("recv packet")
		listData.Append(str)
	}
}

func ShowPcapFile(myApp fyne.App, filePath string) {
	var packetData = []string{}
	var parsedPacket = sniffer.ParsePcapFile(filePath)
	var packDetailData = []sniffer.SniffPacket{}
	listData := binding.BindStringList(&packetData)
	// listData.Set(packetData)
	list := widget.NewListWithData(listData,
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(i binding.DataItem, o fyne.CanvasObject) {
			o.(*widget.Label).Bind(i.(binding.String))
			o.(*widget.Label).TextStyle = fyne.TextStyle{Monospace: true, Bold: true}
			// o.(*widget.Label).Alignment = fyne.TextAlignLeading
			// o.(*widget.Label).Resize(fyne.NewSize(1000, o.MinSize().Height))
		})

	list.OnSelected = func(id widget.ListItemID) {
		if id == 0 {
			list.Unselect(id)
			return
		}
		packet := packDetailData[id-1]
		info := packet.Info
		var showInfo string
		showInfo += "Protocol: " + packet.Protocol + "\n"
		showInfo += "Source MAC address: " + info.SourceMac + "\n"
		showInfo += "Destination MAC address: " + info.DestinationMac + "\n"
		if info.SourceIP != "" && info.DestinationIP != "" {
			showInfo += "Source IP address: " + info.SourceIP + "\n"
			showInfo += "Destination IP address: " + info.DestinationIP + "\n"
		}
		if info.SourcePort != "" && info.DestinationPort != "" {
			showInfo += "Source Port: " + info.SourcePort + "\n"
			showInfo += "Destination Port: " + info.DestinationPort + "\n"
		}
		showInfo += "Data length:  " + info.Size + " Bytes \n"
		showInfo += "Details:  \n" + info.Detail
		detailWindow := front.CreateDetailWindow(myApp, showInfo, info.Dump)
		detailWindow.Show()
		detailWindow.SetOnClosed(func() {
			list.Unselect(id)
		})
	}
	// 创建一个顶层容器，将滚动容器放入其中
	MaxList := container.NewStack(list)
	// 停止抓包
	container := container.NewBorder(nil, nil, nil, nil, MaxList)
	listenWindow := myApp.NewWindow("Listening")
	listenWindow.SetContent(container)
	listenWindow.Resize(fyne.NewSize(1100, 600))
	listenWindow.Show()
	str := fmt.Sprintf("%-5s%-30s%-40s%-40s%-10s", "No.", "Time", "Source", "Destination", "Protocol")
	listData.Append(str)
	for _, packet := range parsedPacket {
		No := len(packDetailData) + 1
		packDetailData = append(packDetailData, packet)
		str := fmt.Sprintf("%-5d%-30s%-40s%-40s%-10s", No, packet.Time, packet.Source, packet.Destination, packet.Protocol)
		// str := "Time\t\t" + packet.Source + "\t\t" + packet.Destination + "\t\t" + packet.Protocol
		// fmt.Println("recv packet")
		listData.Append(str)
	}
}

func main() {

	myApp := app.New()
	mainWindow := myApp.NewWindow("主菜单")
	// myApp.Settings().SetTheme(&front.MyTheme{})
	mainWindow.Resize(fyne.NewSize(400, 300))
	log.Println("app created......")
	log.Println("app running......")

	devicesName := sniffer.GetAllDeviceName()

	Tips := widget.NewLabel("Choose an interface to listen:")

	filterEntry := widget.NewEntry()
	filterEntry.SetPlaceHolder("Input filter...")
	SelectedDeviceName := ""
	selectedInterface := widget.NewSelect(devicesName, func(value string) {
		SelectedDeviceName = value
		log.Println("Select set to", value)
	})

	startButton := widget.NewButton("start listen", func() {
		log.Println("Start listen.....")
		listenChannel := make(chan sniffer.SniffPacket)
		stopChannel := make(chan int)
		if SelectedDeviceName == "" {
			front.CreateTips(myApp, 3)
			return
		}
		if !sniffer.CheckBPFSyntax(SelectedDeviceName, filterEntry.Text) {
			front.CreateTips(myApp, 2)
			return
		}
		go CreateNewListenWindow(myApp, listenChannel, stopChannel)
		go sniffer.Sniff(SelectedDeviceName, listenChannel, stopChannel, filterEntry.Text)
	})

	// var filePath string
	fileDialog := dialog.NewFileOpen(func(file fyne.URIReadCloser, err error) {
		// filePath := file.URI().Path()
		if file != nil {
			filePath := file.URI().Path()
			go ShowPcapFile(myApp, filePath)
		}
		mainWindow.Resize(fyne.NewSize(400, 300))
		// // fmt.Println(file.URI().Path())
		// fmt.Println(filePath)
		// go ShowPcapFile(myApp, filePath)
	}, mainWindow)
	sperateLabel := widget.NewLabelWithStyle("or", fyne.TextAlignCenter, fyne.TextStyle{})
	openfileButton := widget.NewButton("open a pcap file", func() {
		fileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".pcap"}))
		mainWindow.Resize(fyne.NewSize(800, 600))
		fileDialog.Show()
	})
	mainWindow.SetContent(container.NewVBox(Tips, filterEntry, selectedInterface, startButton, sperateLabel, openfileButton))
	mainWindow.ShowAndRun()
}
