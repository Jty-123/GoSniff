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
		go sniffer.Sniff(SelectedDeviceName, listenChannel)

		// gridContainer := container.New(layout.NewGridLayout(3),
		// 	widget.NewLabel("Source"),
		// 	widget.NewLabel("Dest"),
		// 	widget.NewLabel("Protocol"))

		var packetData = []string{}
		listData := binding.BindStringList(&packetData)
		listData.Set(packetData)
		list := widget.NewListWithData(listData,
			func() fyne.CanvasObject {
				return widget.NewLabel("")
			},
			func(i binding.DataItem, o fyne.CanvasObject) {
				o.(*widget.Label).Bind(i.(binding.String))
			})

		// 创建一个顶层容器，将滚动容器放入其中
		MaxList := container.NewStack(list)
		container := container.NewBorder(nil, nil, nil, nil, MaxList)
		listenWindow := myApp.NewWindow("Listening")
		listenWindow.SetContent(container)
		listenWindow.Resize(fyne.NewSize(500, 400))
		listenWindow.Show()
		for {
			select {
			case packet := <-listenChannel:
				str := "Src:" + packet.Source + "    " + "Dst:" + packet.Destionation + "    " + "Protocol:" + packet.Protocol
				listData.Append(str)
			}
		}
	})

	mainWindow.SetContent(container.NewVBox(Tips, selectedInterface, stratButton))
	mainWindow.ShowAndRun()
}
