"""Owned literal-loopback WSGI host without a reverse-DNS dependency."""
from socketserver import TCPServer
from werkzeug.serving import ThreadedWSGIServer


class LoopbackFixtureServer(ThreadedWSGIServer):
    def server_bind(self):
        # HTTPServer.server_bind otherwise calls getfqdn even for 127.0.0.1.
        TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.server_address[1]
