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
	isStop := false // 是否停止
	// 创建一个顶层容器，将滚动容器放入其中
	MaxList := container.NewStack(list)
	var Button *widget.Button // 停止/开始按钮
	// 停止抓包
	Button = widget.NewButton("Stop", func() {
		if Button.Text == "Stop" {
			Button.Text = "Start"
			stopChannel <- 1
			isStop = true
			log.Println("Stop Listen!")
		} else {
			Button.Text = "Stop"
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
		log.Println("Close Listen!")
	})
	listenWindow.SetContent(container)
	listenWindow.Resize(fyne.NewSize(600, 400))
	listenWindow.Show()
	for {
		select {
		case packet := <-listenChannel:
			if isStop {
				// fmt.Println("stop:", isStop)
				continue
			}
			str := "Source:" + packet.Source + "  --->  " + "Destination:" + packet.Destination + "    " + "Protocol:" + packet.Protocol
			// fmt.Println("recv packet")
			listData.Append(str)
			packDetailData = append(packDetailData, packet)
		case sig := <-stopChannel:
			if sig == 1 {
				fmt.Println("STOP")
			} else if sig == 2 {
				fmt.Println("SAVE")
			}
		}
	}
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
		go sniffer.Sniff(SelectedDeviceName, listenChannel, stopChannel, filterEntry.Text)
		go CreateNewListenWindow(myApp, listenChannel, stopChannel)
	})

	mainWindow.SetContent(container.NewVBox(Tips, filterEntry, selectedInterface, stratButton))
	mainWindow.ShowAndRun()
}
