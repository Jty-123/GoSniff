package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/widget"
)

func main() {
	myApp := app.New()

	// 创建一个字符串切片的数据模型
	stringList := binding.NewStringList()

	// 创建一个 List 组件并将其与数据模型关联
	listEntry := widget.NewListWithData(
		stringList,
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(item binding.DataItem, obj fyne.CanvasObject) {
			text, _ := item.(binding.String).Get()
			obj.(*widget.Label).SetText(text)
		},
	)

	// 创建一个按钮，点击后改变字符串切片
	changeButton := widget.NewButton("Change List", func() {
		// 修改字符串切片的值
		stringList.Set([]string{"Item 1", "Item 2", "Item 3"})
	})

	// 将 List 组件和按钮组装在一起
	content := container.NewVBox(
		listEntry,
		changeButton,
	)

	myWindow := myApp.NewWindow("List Binding Example")
	myWindow.SetContent(content)
	myWindow.Resize(fyne.NewSize(200, 200))
	myWindow.ShowAndRun()
}
