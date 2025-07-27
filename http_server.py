from http.server import HTTPServer, SimpleHTTPRequestHandler

class NoCacheHTTPRequestHandler(SimpleHTTPRequestHandler):
    def send_response_only(self, code, message=None):
        # Always respond with 200, even if cached
        if code == 304:
            code = 200
        super().send_response_only(code, message)

    def end_headers(self):
        # Add headers to prevent browser caching
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

if __name__ == '__main__':
    port = 8000
    server_address = ('', port)
    httpd = HTTPServer(server_address, NoCacheHTTPRequestHandler)
    print(f"Serving HTTP on 0.0.0.0 port {port} (http://0.0.0.0:{port}/)")
    httpd.serve_forever()
