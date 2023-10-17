package main

import (
	"GoSniff/sniffer"
	"log"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/widget"
)

var SelectedDeviceName string

func main() {
	myApp := app.New()
	mainWindow := myApp.NewWindow("main")

	mainWindow.Resize(fyne.NewSize(400, 300))
	log.Println("app created......")
	log.Println("app running......")

	devicesName := sniffer.GetAllDeviceName()

	Tips := widget.NewLabel("Choose the interface to listen:")

	selectedInterface := widget.NewSelect(devicesName, func(value string) {
		SelectedDeviceName = value
		log.Println("Select set to", value)
	})

	stratButton := widget.NewButton("start listen", func() {
		log.Println("Start listen.....")
		listenChannel := make(chan sniffer.SniffPacket)
		stopChannel := make(chan bool)
		go sniffer.Sniff(SelectedDeviceName, listenChannel, stopChannel)

		// gridContainer := container.New(layout.NewGridLayout(3),
		// 	widget.NewLabel("Source"),
		// 	widget.NewLabel("Dest"),
		// 	widget.NewLabel("Protocol"))

		var packetData = []string{}
		var packDetailData = []sniffer.SniffPacket{}
		listData := binding.BindStringList(&packetData)
		listData.Set(packetData)
		list := widget.NewListWithData(listData,
			func() fyne.CanvasObject {
				return widget.NewLabel("")
			},
			func(i binding.DataItem, o fyne.CanvasObject) {
				o.(*widget.Label).Bind(i.(binding.String))
			})

		list.OnSelected = func(id widget.ListItemID) {
			packet := packDetailData[id]
			info := packet.Info
			var showInfo string
			showInfo += "Protocol:  " + packet.Protocol + "\n"
			showInfo += "Source MAC address:  " + info.SourceMac + "\n"
			showInfo += "Destination MAC address:  " + info.DestinationMac + "\n"
			if info.SourceIP != "" && info.DestinationIP != "" {
				showInfo += "Source IP address:  " + info.SourceIP + "\n"
				showInfo += "Destination IP address:  " + info.DestinationIP + "\n"
			}
			if info.SourcePort != "" && info.DestinationPort != "" {
				showInfo += "Source Port:  " + info.SourcePort + "\n"
				showInfo += "Destination Port:  " + info.DestinationPort + "\n"
			}
			showInfo += "Data length:  " + info.DataLen + " Bytes \n"
			showInfo += "Details:  \n" + info.Detail
			detailWindow := myApp.NewWindow("Packet Detail")
			detailWindow.Resize(fyne.NewSize(600, 400))
			//text := canvas.NewText(showInfo, color.Black)
			entry := widget.NewMultiLineEntry()
			entry.SetText(showInfo)
			// container := container.NewStack(text)
			detailWindow.SetContent(entry)
			detailWindow.Show()
		}
		// 创建一个顶层容器，将滚动容器放入其中
		MaxList := container.NewStack(list)
		// 停止抓包
		Button := widget.NewButton("Stop", func() {
			stopChannel <- false
		})
		container := container.NewBorder(nil, Button, nil, nil, MaxList)
		listenWindow := myApp.NewWindow("Listening")
		listenWindow.SetContent(container)
		listenWindow.Resize(fyne.NewSize(600, 400))
		listenWindow.Show()
		for {
			select {
			case packet := <-listenChannel:
				str := "Src:" + packet.Source + "  --->  " + "Dst:" + packet.Destination + "    " + "Protocol:" + packet.Protocol
				listData.Append(str)
				packDetailData = append(packDetailData, packet)
			case <-stopChannel:
				break
			}
		}

	})

	mainWindow.SetContent(container.NewVBox(Tips, selectedInterface, stratButton))
	mainWindow.ShowAndRun()
}
