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
            page = self.unpack_headers(request).strip()
            self.send_payload(sock, page)
        except Exception as e:
            logger.debug('Error handling client: {} :: {}'.format(addr,str(e)[:200]))
            self.default(sock)
        sock.close()

    def unpack_headers(self, headers):
        h = headers.splitlines()[0]
        page = h.split(" ")
        return page[1][1:]

    def send_payload(self, sock, page):
        file = os.path.join(os.path.expanduser('~'), '.ar3', 'scripts', page)
        if os.path.exists(file):
                data_count = 0
                self.resp += "Content-Type: text/plain; charset-utf-8\r\n\r\n"
                self.resp += clean_ps_script(file)
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
        print('[-] Agent server failed to bind: localhost:443')
        exit(1)
    sock.listen(20)

    while True:
        client_socket, addr = sock.accept()
        try:
            logger.debug('New HTTP connection from {}'.format(addr))
            Thread(target=RequestHandler, args=(client_socket,addr,logger,), daemon=True).start()
        except Exception as e:
            try:
                client_socket.close()
            except:
                pass