"""Standalone Authasaurus reverse proxy."""

from http.server import HTTPServer, BaseHTTPRequestHandler


class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'

    def do_POST(self, body=True):
        try:
            req_header = self.headers
            body = self.rfile.read()
            self.rfile.close()
            print(f"Got body: {body}")
            self.send_response(200)
            for key, value in req_header.items():
                self.send_header(key, value)
            # self.send_resp_headers(req_header, 11)
            self.end_headers()
            self.wfile.write(bytes(f"Request: {self.requestline}\n", 'utf-8'))
            # self.wfile.write(body)
        finally:
            self.wfile.flush()

if __name__ == '__main__':
    server_address = ('127.0.0.1', 8081)
    httpd = HTTPServer(server_address, ProxyHTTPRequestHandler)
    print('http server is running')
    httpd.serve_forever()
