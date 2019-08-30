import ssl
from io import BytesIO
from http.server import HTTPServer, BaseHTTPRequestHandler

class RequestHandler(BaseHTTPRequestHandler):

    def shutdown(self):
        self.shutdown()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'Hello, world!')

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        self.send_response(200)
        self.end_headers()
        response = BytesIO()
        response.write(b'This is POST request. ')
        response.write(b'Received: ')
        response.write(body)
        self.wfile.write(response.getvalue())


httpd = HTTPServer((ip, port), BaseHTTPRequestHandler)
httpd.socket = ssl.wrap_socket (httpd.socket, keyfile="~/.ar3/key.pem", certfile='~/.ar3/cert.pem', server_side=True)
httpd.serve_forever()
