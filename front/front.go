package front

// 该文件主要负责一些纯界面的操作

import (
	_ "embed"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// 创建提示窗
func CreateTips(myApp fyne.App, tipType int) {
	// tipType
	// 1 提示在save前应该stop
	// 2 提示BPF的语法出现错误
	// 3 提示没有选择监听的网卡
	switch tipType {
	case 1:
		tipWindow := myApp.NewWindow("Warnning")
		tipWindow.Resize(fyne.NewSize(200, 100))
		tips := widget.NewLabel("Please stop before save.")
		botton := widget.NewButton("ok", func() {
			tipWindow.Close()
		})
		container := container.NewVBox(tips, botton)
		tipWindow.SetContent(container)
		tipWindow.Show()
	case 2:
		tipWindow := myApp.NewWindow("Warnning")
		tipWindow.Resize(fyne.NewSize(200, 100))
		tips := widget.NewLabel("BPF syntax error!")
		botton := widget.NewButton("ok", func() {
			tipWindow.Close()
		})
		container := container.NewVBox(tips, botton)
		tipWindow.SetContent(container)
		tipWindow.Show()
	case 3:
		tipWindow := myApp.NewWindow("Warnning")
		tipWindow.Resize(fyne.NewSize(200, 100))
		tips := widget.NewLabel("Must choose a interface before listen.")
		botton := widget.NewButton("ok", func() {
			tipWindow.Close()
		})
		container := container.NewVBox(tips, botton)
		tipWindow.SetContent(container)
		tipWindow.Show()
	}
}

// 创建详情窗
func CreateDetailWindow(myApp fyne.App, showInfo string, dump string) fyne.Window {
	detailWindow := myApp.NewWindow("Packet Detail")
	detailWindow.Resize(fyne.NewSize(700, 600))
	//text := canvas.NewText(showInfo, color.Black)
	entryInfo := widget.NewMultiLineEntry()
	entryDump := widget.NewMultiLineEntry()
	entryInfo.TextStyle = fyne.TextStyle{Monospace: true, Bold: true}
	entryDump.TextStyle = fyne.TextStyle{Monospace: true, Bold: true}
	entryInfo.SetText(showInfo)
	entryDump.SetText(dump)
	container := container.NewGridWithRows(2, entryInfo, entryDump)
	detailWindow.SetContent(container)
	return detailWindow
}
