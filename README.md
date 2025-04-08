# 🖥️ Terminal Plugin for IDA Pro

A lightweight terminal integration for [IDA Pro](https://hex-rays.com/ida-pro/) that lets you open a fully functional terminal within the IDA GUI.  
Quickly access shell commands, scripts, or tooling without leaving your reversing environment.

---

## 🚀 Features

- Open a terminal window directly inside IDA Pro  
- Instant access with `Ctrl+Shift+T`  
- Seamlessly integrated using Qt

---

## 🛠 Usage

Once the plugin is installed:

- Press `Ctrl+Shift+T` to toggle the terminal window inside IDA Pro.
- Run shell commands as you would in a regular terminal.

---

## 🔗 Credits

The terminal window is powered by [termqt](https://github.com/TerryGeng/termqt), a Qt-based terminal emulator.

---

## 📁 Installation

1. Clone this repo or download the plugin binary.
2. Place the plugin in your IDA `plugins/` directory.
3. Restart IDA Pro.

---

## Limitations 

Currently only works on 

- MacOS
- Linux 

## 🧩 Compatibility

- Tested with IDA Pro 9.1+ on **MacOS**

---

## 📜 License

MIT License 

---

## 🙌 Acknowledgements

Big thanks to [TerryGeng](https://github.com/TerryGeng) for building [termqt](https://github.com/TerryGeng/termqt), which made this integration possible.