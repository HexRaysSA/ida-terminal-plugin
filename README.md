⚠️This is a very preliminary version ... comments & suggestions are more than welcome. 

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

## 📁 Installation

1. Clone this repo in your IDA `$HOME/.idapro/plugins/` directory.
2. Restart IDA Pro.

## ⚙️ Configuration

Rename config.example.py to config.py to customize the behaviour.

---

## Limitations 

Currently only works on 

- MacOS
- Linux 

## 🧩 Compatibility

- Tested with IDA Pro 9.1+ on **MacOS**

---

## 🔗 Credits

The terminal window is powered by [termqt](https://github.com/TerryGeng/termqt), a Qt-based terminal emulator.

---

## 📜 License

MIT License 

---

## 🙌 Acknowledgements

Big thanks to [TerryGeng](https://github.com/TerryGeng) for building [termqt](https://github.com/TerryGeng/termqt), which made this integration possible.