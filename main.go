package main

import (
	"GoSniff/sniffer"
	"fmt"
	"log"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/widget"
)

var SelectedDeviceName string

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
			o.(*widget.Label).TextStyle = fyne.TextStyle{Bold: true}
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
		showInfo += "Data length:  " + info.Size + " Bytes \n"
		showInfo += "Details:  \n" + info.Detail
		detailWindow := myApp.NewWindow("Packet Detail")
		detailWindow.Resize(fyne.NewSize(600, 600))
		//text := canvas.NewText(showInfo, color.Black)
		entryInfo := widget.NewMultiLineEntry()
		entryBinary := widget.NewMultiLineEntry()
		entryAscii := widget.NewMultiLineEntry()
		entryInfo.SetText(showInfo)
		entryBinary.SetText(info.BinaryHex)
		entryAscii.SetText(info.AsciiText)
		buttom := container.NewGridWithColumns(2, entryBinary, entryAscii)
		container := container.NewGridWithRows(2, entryInfo, buttom)
		detailWindow.SetContent(container)
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
		if isStop == false {
			createTips(myApp, 1)
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
	listenWindow.Resize(fyne.NewSize(700, 400))
	listenWindow.Show()
	str := fmt.Sprintf("%-10s%-50s%-50s%-30s%-15s", "No.", "Time", "Source", "Destination", "Protocol")
	listData.Append(str)
	for packet := range listenChannel {
		No := len(packDetailData) + 1
		packDetailData = append(packDetailData, packet)
		str := fmt.Sprintf("%-10d%-35s%-45s%-30s%-15s", No, packet.Time, packet.Source, packet.Destination, packet.Protocol)
		// str := "Time\t\t" + packet.Source + "\t\t" + packet.Destination + "\t\t" + packet.Protocol
		// fmt.Println("recv packet")
		listData.Append(str)
	}
	// for {
	// 	select {
	// 	case packet := <-listenChannel:
	// 		str := "Source:" + packet.Source + "  --->  " + "Destination:" + packet.Destination + "    " + "Protocol:" + packet.Protocol
	// 		// fmt.Println("recv packet")
	// 		listData.Append(str)
	// 		packDetailData = append(packDetailData, packet)
	// 	}
	// }
}

func createTips(myApp fyne.App, tipType int) {
	// tipType
	// 1 提示在save前应该stop
	// 2 提示BPF的语法出现错误
	switch tipType {
	case 1:
		tipWindow := myApp.NewWindow("Warnning")
		tipWindow.Resize(fyne.NewSize(200, 100))
		tips := widget.NewLabel("Please stop before save")
		botton := widget.NewButton("ok", func() {
			tipWindow.Close()
		})
		container := container.NewVBox(tips, botton)
		tipWindow.SetContent(container)
		tipWindow.Show()
	case 2:
		tipWindow := myApp.NewWindow("Warnning")
		tipWindow.Resize(fyne.NewSize(200, 100))
		tips := widget.NewLabel("BPF syntax error")
		botton := widget.NewButton("ok", func() {
			tipWindow.Close()
		})
		container := container.NewVBox(tips, botton)
		tipWindow.SetContent(container)
		tipWindow.Show()
	}

}

func main() {

	myApp := app.New()
	mainWindow := myApp.NewWindow("main")

	mainWindow.Resize(fyne.NewSize(400, 300))
	log.Println("app created......")
	log.Println("app running......")

	devicesName := sniffer.GetAllDeviceName()

	Tips := widget.NewLabel("Choose the interface to listen:")

	filterEntry := widget.NewEntry()
	filterEntry.SetPlaceHolder("Input filter...")

	selectedInterface := widget.NewSelect(devicesName, func(value string) {
		SelectedDeviceName = value
		log.Println("Select set to", value)
	})

	stratButton := widget.NewButton("start listen", func() {
		log.Println("Start listen.....")
		listenChannel := make(chan sniffer.SniffPacket)
		stopChannel := make(chan int)
		go CreateNewListenWindow(myApp, listenChannel, stopChannel)
		go sniffer.Sniff(SelectedDeviceName, listenChannel, stopChannel, filterEntry.Text)
	})

	mainWindow.SetContent(container.NewVBox(Tips, filterEntry, selectedInterface, stratButton))
	mainWindow.ShowAndRun()
}
