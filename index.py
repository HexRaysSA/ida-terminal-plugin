import importlib.util
import logging
import os
import platform

import ida_auto
import ida_idaapi
import ida_kernwin
import ida_loader
from PyQt5 import QtWidgets, QtGui, QtCore, sip

from termqt import Terminal

dependencies_loaded = True
failed_dependency = []


class TerminalPlugin(ida_idaapi.plugin_t):
    config = {}
    flags = ida_idaapi.PLUGIN_FIX
    comment = "Terminal Plugin"
    help = "Terminal"
    wanted_name = "Terminal"
    wanted_hotkey = "Ctrl-Shift-T"

    def __init__(self):
        super().__init__()
        script_dir = os.path.dirname(os.path.abspath(__file__))
        self.config = load_config_dict(os.path.join(script_dir, "config.py"))
        self.view = None

    def init(self):
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        try:
            self.view = TerminalView(self.config)
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
    config = {}

    def __init__(self, config):
        super(TerminalView, self).__init__()
        self.visible = False
        self.config = config

        self._ui_init_widget()
        self._ui_layout()

        self.show()

    def show(self):
        self.refresh()

        # show the dockable widget
        ida_kernwin.display_widget(self._twidget, 0)
        ida_kernwin.set_dock_pos(self.WINDOW_TITLE, "Output", ida_kernwin.DP_TAB)

    def refresh(self):
        pass

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
        # make this configurable
        logger.setLevel(logging.ERROR)
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
            bin = self.config["CMD"] or os.getenv('SHELL')
            work_dir = self.config["WORK_DIR"] or os.getenv('HOME')

            from termqt import TerminalPOSIXExecIO
            terminal_io = TerminalPOSIXExecIO(
                terminal.row_len,
                terminal.col_len,
                bin,
                logger=logger,
                work_dir=work_dir
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


def load_config_dict(filepath: str) -> dict:
    config = {
        "CMD": None,
        "WORK_DIR": None,
    }

    if not os.path.exists(filepath):
        return config  # empty dict

    spec = importlib.util.spec_from_file_location("config_module", filepath)
    module = importlib.util.module_from_spec(spec)

    try:
        spec.loader.exec_module(module)
        for key in dir(module):
            if not key.startswith("_"):
                config[key] = getattr(module, key)
    except Exception as e:
        print(f"Warning: Failed to load config from {filepath}: {e}")

    print (config)
    return config
