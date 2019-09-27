from __future__ import print_function
import ast
from collections import defaultdict
from collections import namedtuple
import json
import re
import sys
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse

ParsedMessage = namedtuple('ParsedMessage', ['data', 'offset', 'level'])

TIMESTAMP = r'^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[,.]\d{3})'
PID = r'(?P<pid>\d+)'
LEVEL = r'(?P<level>[A-Z]+)'
CLIENT = r'(\[?tempest\.lib\.common\.rest_client\]?)'
SP_REQ_ID = r'(\s+\[(?P<req_id>[a-z0-9-]+)\s*\])?'
FUNC = r'\((?P<function>[^)]+)\):'
STATUS = r'(?P<status>\d{3})'
METHOD = r'(?P<method>[A-Z]+)'
URL = r'(?P<url>\S+)'
SP_INFO_TAIL = r'\s*(?P<tail>.*)'
SP = r'\s+'
DEBUG_REQ = r'Request - Headers:\s+(?P<req_headers>.*)\n\s*Body: (?P<req_body>.*)\n'
DEBUG_RESP =r'\s*Response - Headers: (?P<resp_headers>.*)\n\s*Body: (?P<resp_body>.*?)(?:_log_request_full.*)?'

LOGLINE_START = TIMESTAMP + SP + PID + SP + LEVEL
LOGLINE_TEMPEST = SP + CLIENT + SP_REQ_ID
LOGLINE_INFO = SP + 'Request' + SP + FUNC + SP + STATUS + SP + METHOD + SP + URL + SP_INFO_TAIL
LOGLINE_DEBUG = SP + DEBUG_REQ + DEBUG_RESP

RE_LOGLINE_START = re.compile(LOGLINE_START)
RE_LOGLINE_TEMPEST = re.compile(LOGLINE_TEMPEST)
RE_LOGLINE_INFO = re.compile(LOGLINE_INFO)
RE_LOGLINE_DEBUG = re.compile(LOGLINE_DEBUG)


class TempestRequest(object):
    def __init__(self, method, url, headers=None, body=None):
        self.method = method
        self.url = urlparse(url)
        self.headers = headers
        self.body = body

    def __str__(self):
        return "{} {}\nheaders={}\nbody={}".format(self.method, self.url.geturl(),
                                                   self.headers,
                                                   self.body)

    @property
    def target(self):
        if self.url.port == 9696:
            return 'Neutron'
        elif self.url.path.startswith('/compute') or self.url.port in {8773, 8774, 8775}:
            return 'Nova'
        elif self.url.path.startswith('/identity') or self.url.port in {5000, 35357}:
            return 'Keystone'
        elif self.url.path.startswith('/volume') or self.url.port == 8776:
            return 'Cinder'
        elif self.url.path.startswith('/image') or self.url.port == 9292:
            return 'Glance'
        elif self.url.port == 9876:
            return 'Octavia'

        port = self.url.port or 443 if self.url.scheme == 'https' else 80
        return "{}.{}".format(self.url.hostname, port)

    @classmethod
    def from_lines(cls, info, debug):
        pass


class TempestResponse(object):
    def __init__(self, status, headers=None, body=None):
        self.status = status
        self.headers = headers
        self.body = body

    def __str__(self):
        return "{}\nheaders={}\nbody={}\n".format(self.status, self.headers, self.body)

    @classmethod
    def from_lines(cls, info, debug):
        pass


class TempestLogItem(object):
    def __init__(self, req_id, function, req=None, resp=None, time=None):
        self.req_id = req_id
        self.function = function
        self.request = req
        self.response = resp
        self.time = time

    @classmethod
    def from_lines(cls, req_id, info, debug):
        info_match = RE_LOGLINE_INFO.match(info.data, pos=info.offset)
        function = info_match.groupdict()['function']
        debug_match = RE_LOGLINE_DEBUG.match(debug.data, pos=debug.offset)
        try:
            req_body = debug_match.groupdict()['req_body']
        except Exception:
            print(debug.data[debug.offset:])
            raise
        try:
            req_body = ast.literal_eval(req_body)
        except Exception:
            pass
        resp_body = debug_match.groupdict()['resp_body']
        try:
            resp_body = ast.literal_eval(resp_body)
            resp_body = json.loads(resp_body)
        except Exception:
            pass
        request = TempestRequest(method=info_match.groupdict()['method'],
                                 url=info_match.groupdict()['url'],
                                 headers=ast.literal_eval(debug_match.groupdict()['req_headers']),
                                 body=req_body)
        response = TempestResponse(status=info_match.groupdict()['status'],
                                   headers=ast.literal_eval(debug_match.groupdict()['resp_headers']),
                                   body=resp_body)
        time = info_match.groupdict()['tail']
        item = cls(req_id, function, request, response, time)
        return item

    def __str__(self):
        return "{}({}) {} {} {}".format(self.req_id, self.function, self.response.status, self.request.method, self.request.url.path)

    def to_diagram(self):
        note = '\nNote right of {host}: {time}'.format(host=self.request.target, time=self.time) if self.time else ''
        return "Client->{host}: {method} {path}{note}\n{host}->Client: {status}".format(method=self.request.method, host=self.request.target, path=self.request.url.path, status=self.response.status, note=note)


def messages(f):
    message = ""
    offset = 0
    level = None
    for line in f:
        match = RE_LOGLINE_START.match(line)
        if match:
            if message:
                yield ParsedMessage(message, offset, level)
            message = line
            offset = match.end(match.lastindex)
            level = match.groupdict()['level']
        else:
            message += line
    yield ParsedMessage(message, offset, level)


def message_pair(messages):
    outstanding = defaultdict(list)
    for msg in messages:
        match = RE_LOGLINE_TEMPEST.search(msg.data, pos=msg.offset)
        if match:
            req_id = match.groupdict()['req_id']
            offset = match.end(match.lastindex)
            if req_id in outstanding or req_id is None and msg.level == 'DEBUG':
                # req_id is optional in the logs, if it is missing just assume
                # we have an INFO tempest client log followed by a DEBUG one
                outstanding[req_id].append(ParsedMessage(msg.data, offset, msg.level))
                yield TempestLogItem.from_lines(req_id, *outstanding.pop(req_id))
            else:
                outstanding[req_id].append(ParsedMessage(msg.data, offset, msg.level))


try:
    filename = sys.argv[1]
except IndexError:
    filename = 'test.txt'

template = """<html>
<head>
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.4.1/jquery.min.js"></script>
<script src="bower_components/bower-webfontloader/webfont.js"></script>
<script src="bower_components/snap.svg/dist/snap.svg-min.js"></script>
<script src="bower_components/underscore/underscore-min.js"></script>
<script src="bower_components/js-sequence-diagrams/dist/sequence-diagram-min.js"></script>
</head>
<body>
<div class="diagram">
%s
</div>
<script>
$(".diagram").sequenceDiagram({theme: 'simple'});
</script>

</body>
</html>
"""

with open(filename, 'r') as f:
    body = "\n".join(msg.to_diagram() for msg in message_pair(messages(f)))
    print(template % (body,))
