#!/usr/bin/python3
"""Native elementary shell for the existing loopback NmapUI service."""
from pathlib import Path
import time
import gi
gi.require_version('Gtk', '4.0')
gi.require_version('WebKit', '6.0')
from gi.repository import Gio, GLib, Gtk, WebKit

ORIGIN = 'http://127.0.0.1:9000'

class Desktop(Gtk.Application):
    def __init__(self):
        super().__init__(application_id='org.techmore.NmapUI')
        self.window = None

    def do_activate(self):
        if self.window:
            self.window.present()
            return
        data = Path(GLib.get_user_data_dir()) / 'nmapui/desktop'
        data.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.session = WebKit.NetworkSession.new(str(data), str(data / 'cache'))
        self.session.get_cookie_manager().set_persistent_storage(str(data / 'cookies.sqlite'), WebKit.CookiePersistentStorage.SQLITE)
        self.session.connect('download-started', self.download)
        self.web = WebKit.WebView(network_session=self.session)
        self.web.connect('create', self.popup)
        self.window = Gtk.ApplicationWindow(application=self, title='TM NmapUI', default_width=1180, default_height=800)
        self.window.connect('close-request', self.closed)
        header = Gtk.HeaderBar()
        refresh = Gtk.Button(icon_name='view-refresh-symbolic', tooltip_text='Refresh')
        refresh.connect('clicked', lambda *_: self.web.reload())
        header.pack_start(refresh)
        browser = Gtk.Button(icon_name='web-browser-symbolic', tooltip_text='Open in browser')
        browser.connect('clicked', lambda *_: Gio.AppInfo.launch_default_for_uri(ORIGIN, None))
        header.pack_end(browser)
        self.window.set_titlebar(header)
        self.window.set_child(self.web)
        self.web.load_uri(ORIGIN)
        self.window.present()

    def closed(self, *_):
        self.window = None
        return False

    def popup(self, source, navigation):
        view = WebKit.WebView.new_with_related_view(source)
        window = Gtk.ApplicationWindow(application=self, title='NmapUI Sign In', default_width=700, default_height=750)
        window.set_child(view)
        view.connect('close', lambda *_: window.destroy())
        window.present()
        return view

    def download(self, session, download):
        def destination(item, suggested):
            directory = Path(GLib.get_user_special_dir(GLib.UserDirectory.DIRECTORY_DOWNLOAD) or Path.home() / 'Downloads')
            directory.mkdir(parents=True, exist_ok=True)
            target = directory / (Path(suggested).name or 'nmapui-report')
            if target.exists():
                target = directory / (str(time.time_ns()) + '-' + target.name)
            item.set_destination(target.as_uri())
            return True
        download.connect('decide-destination', destination)

if __name__ == '__main__':
    Desktop().run()
