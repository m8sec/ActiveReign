import os
import socket
from threading import Thread

from ar3.helpers.powershell import clean_ps_script

class RequestHandler():
    def __init__(self, sock, addr, logger):
        self.logger = logger
        self.resp =  "HTTP/1.1 200 OK\r\n"
        self.resp += "Server: IIS\r\n"

        try:
            request = sock.recv(4096).decode('utf-8')
            headers = self.unpack_headers(request)
            page = self.get_page(headers)

            logger.info(["{}:{}".format(addr[0], addr[1]), addr[0], "HTTP SERVER", headers[0]])
            self.send_payload(sock, page)
        except Exception as e:
            logger.debug(["{}:{}".format(addr[0], addr[1]), addr[0], "HTTP SERVER", str(e)])
            self.default(sock)
        sock.close()

    def unpack_headers(self, headers):
        return headers.splitlines()

    def get_page(self,headers):
        page = headers[0].split(" ")
        return page[1][1:]

    def send_payload(self, sock, page):
        file = os.path.join(os.path.expanduser('~'), '.ar3', 'scripts', page)
        if os.path.exists(file):
                payload = clean_ps_script(file)
                self.resp += "Content-Type: text/plain; charset-utf-8\r\n"
                self.resp += "Content-Length: {}\r\n\r\n".format(len(payload))
                self.resp += payload
                sock.sendall(self.resp.encode('UTF-8'))
                self.logger.debug("Finished serving payload: {}".format(page))
        else:
            self.logger.debug('Invalid payload requested: \'{}\''.format(page))

    def default(self, sock):
        self.resp += "Content-Type: text/html\r\n\r\n"
        self.resp += "<html><body>It Works!</body></html>"
        sock.send(self.resp.encode('UTF-8'))

def ar3_server(logger):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(('0.0.0.0', 80))
    except:
        logger.fail("HTTP server failed to bind to 0.0.0.0:80")
        exit(1)
    sock.listen(20)

    while True:
        client_socket, addr = sock.accept()
        try:
            Thread(target=RequestHandler, args=(client_socket,addr,logger,), daemon=True).start()
        except Exception as e:
            try:
                client_socket.close()
            except:
                pass