import ida_idaapi
import ida_auto
import ida_loader
import ida_kernwin
import platform
from termqt import Terminal
import logging

import os
from PyQt5 import QtWidgets, QtGui, QtCore, sip

dependencies_loaded = True
failed_dependency = []


class TerminalPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_FIX
    comment = "Terminal Plugin"
    help = "Terminal"
    wanted_name = "Terminal"
    wanted_hotkey = "Ctrl-Shift-T"

    def __init__(self):
        super().__init__()
        self.view = None

    def init(self):
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        try:
            self.view = TerminalView()
        except Exception as e:
            ida_kernwin.msg(f"Terminal, exception {e} trying to run plugin.")

    def term(self):
        try:
            if self.view is not None:
                self.view = None
        except Exception as e:
            ida_kernwin.msg(f"Terminal plugin, exception {e} trying to unhook hooks.")

        self.view = None

    def test(self):
        pass


def PLUGIN_ENTRY():
    return TerminalPlugin()


class TerminalView(QtWidgets.QWidget):
    WINDOW_TITLE = "Terminal"

    def __init__(self):
        super(TerminalView, self).__init__()
        self.visible = False

        self._ui_init_widget()
        self._ui_layout()

        self.show()

    def show(self):
        self.refresh()

        # show the dockable widget
        ida_kernwin.display_widget(self._twidget, 0)
        ida_kernwin.set_dock_pos(self.WINDOW_TITLE, "Output", ida_kernwin.DP_TAB)

    def refresh(self):
        print("refresh")

    def _cleanup(self):
        self.visible = False
        self._twidget = None
        self.widget = None

    def _ui_init_widget(self):
        # create a dockable widget, and save a reference to it for later use
        self._twidget = ida_kernwin.create_empty_widget(self.WINDOW_TITLE)

        # cast the IDA 'twidget' to a less opaque QWidget object
        self.widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(self._twidget)

        # hooks to help track the container/widget lifetime
        class ExplorerUIHooks(ida_kernwin.UI_Hooks):
            def widget_invisible(_, twidget):
                if twidget == self._twidget:
                    self.visible = False
                    self._cleanup()

            def widget_visible(_, twidget):
                if twidget == self._twidget:
                    self.visible = True

        # install the widget lifetime hooks
        self._ui_hooks = ExplorerUIHooks()
        self._ui_hooks.hook()

    def _ui_layout(self):
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        handler = logging.StreamHandler()
        formatter = logging.Formatter("[%(asctime)s] > " "[%(filename)s:%(lineno)d] %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)

        main_layout = QtWidgets.QHBoxLayout()
        main_layout.setContentsMargins(1, 0, 0, 0)

        terminal = Terminal(200, 200, logger=logger)
        terminal.set_font()
        terminal.maximum_line_history = 2000
        scroll = QtWidgets.QScrollBar(QtCore.Qt.Vertical, terminal)
        terminal.connect_scroll_bar(scroll)

        main_layout.addWidget(terminal)
        main_layout.addWidget(scroll)
        main_layout.setSpacing(0)

        # apply the layout to the widget
        self.widget.setLayout(main_layout)

        auto_wrap_enabled = True

        pl = platform.system()

        if pl in ["Linux", "Darwin"]:
            bin = os.getenv('SHELL') or "/bin/bash"

            from termqt import TerminalPOSIXExecIO
            terminal_io = TerminalPOSIXExecIO(
                terminal.row_len,
                terminal.col_len,
                bin,
                logger=logger
            )
        elif pl == "Windows":
            bin = "cmd"

            from termqt import TerminalWinptyIO
            terminal_io = TerminalWinptyIO(
                terminal.row_len,
                terminal.col_len,
                bin,
                logger=logger
            )

            # it turned out that cmd prefers to handle resize by itself
            # see https://github.com/TerryGeng/termqt/issues/7
            auto_wrap_enabled = False
        else:
            logger.error(f"Platform not supported: {platform}")

        terminal.enable_auto_wrap(auto_wrap_enabled)

        if terminal_io is not None:
            terminal_io.stdout_callback = terminal.stdout
            terminal.stdin_callback = terminal_io.write
            terminal.resize_callback = terminal_io.resize
            terminal_io.spawn()
