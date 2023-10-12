package main

import (
	"GoSniff/sniffer"
	"log"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
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
		go sniffer.Sniff(SelectedDeviceName)
		listenWindow := myApp.NewWindow("Listening")
		listenWindow.Resize(fyne.NewSize(800, 600))
		listenWindow.Show()
	})

	mainWindow.SetContent(container.NewVBox(Tips, selectedInterface, stratButton))
	mainWindow.ShowAndRun()
}
