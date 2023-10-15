package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

func main() {
	myApp := app.New()

	// 创建一个网格布局，将三个输入框放入一行中
	gridContainer := container.New(layout.NewGridLayout(3),
		widget.NewLabel("Source"),
		widget.NewLabel("Dest"),
		widget.NewLabel("Protocol"))

	// 创建一个滚动容器，用于显示数据
	// scrollContainer := container.NewScroll(gridContainer)
	var data = []string{}
	listData := binding.BindStringList(&data)
	listData.Set(data)
	list := widget.NewListWithData(listData,
		func() fyne.CanvasObject {
			return widget.NewLabel("template")
		},
		func(i binding.DataItem, o fyne.CanvasObject) {
			o.(*widget.Label).Bind(i.(binding.String))
		})

	// 创建一个顶层容器，将滚动容器放入其中
	MaxList := container.NewStack(list)
	container := container.NewBorder(gridContainer, nil, nil, nil, MaxList)

	go func() {
		for i := 0; i < 2; i++ {
			listData.Append("d")
		}
	}()
	// 创建一个窗口并将顶层容器放入其中
	myWindow := myApp.NewWindow("Packet Data Viewer")
	myWindow.SetContent(container)
	myWindow.Resize(fyne.NewSize(800, 600))
	// 启动应用
	myWindow.ShowAndRun()

}
