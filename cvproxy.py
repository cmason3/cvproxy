#!/usr/bin/env python3

# CVProxy - CloudVision Proxy
# Copyright (c) 2026 Chris Mason <chris@netnix.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import asyncio, io, os, sys, socket, signal, jsonschema, base64, threading
import argparse, urllib3, time, tempfile, json, logging, datetime, dataclasses
from http.server import HTTPServer, BaseHTTPRequestHandler

from pyavd._cv.client import CVClient
from pyavd._cv.workflows.deploy_to_cv import deploy_to_cv
from pyavd._cv.workflows.models import CloudVision, CVDevice, CVEosConfig, CVChangeControl

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.getLogger().setLevel(logging.ERROR)

__version__ = '1.0.1'

schema = {
  'unevaluatedProperties': False,
  'required': ['devices', 'cv_server', 'cv_token'],
  'properties': {
    'devices': {
      'minProperties': 1,
      'unevaluatedProperties': False,
      'patternProperties': {
        '^[a-z][a-z0-9_.-]*$': {
          'unevaluatedProperties': False,
          'required': ['configlet'],
          'properties': {
            'serial_number': { 'type': 'string', 'pattern': '^[A-Z][A-Z0-9]{10}$' },
            'configlet': { 'type': 'string', 'pattern': '^(?=(.{4})+$)[A-Za-z0-9+/-]+={0,2}$' }
          }
        }
      }
    },
    'cv_server': { 'type': 'string', 'minLength': 1 },
    'cv_token': { 'type': 'string', 'minLength': 1 },
    'cv_change_control_name': { 'type': 'string', 'minLength': 1 },
    'cv_delete_workspace': { 'type': 'boolean' }
  }
}

llock = threading.RLock()

async def deploy(cv, configs, change_control=False, strict_tags=False, delete_workspace=False):
  r = await deploy_to_cv(cloudvision=cv, configs=configs, change_control=change_control, strict_tags=strict_tags)

  if delete_workspace and r.workspace.id:
    async with CVClient(servers=cv.servers, token=cv.token, username=cv.username, password=cv.password, verify_certs=cv.verify_certs) as cv_client:
      await cv_client.delete_workspace(workspace_id=r.workspace.id)

  return r

class CVProxyRequest(BaseHTTPRequestHandler):
  server_version = 'CVProxy/' + __version__
  protocol_version = 'HTTP/1.1'

  def log_message(self, format, *args):
    if int(args[1]) >= 400:
      rcode = f'\033[31m{args[1]}\033[0m'
    elif self.status == 'error':
      rcode = f'\033[33m{args[1]}\033[0m'
    else:
      rcode = f'\033[32m{args[1]}\033[0m'

    if self.args.xff and 'X-Forwarded-For' in self.headers:
      log(f'[{self.headers["X-Forwarded-For"]}] [{rcode}] {args[0]}')

    else:
      log(f'[{self.address_string()}] [{rcode}] {args[0]}')

  def __getattr__(self, attr):
    if attr.startswith('do_') and attr != 'do_POST':
      return self.do_405
    else:
      return super().__getattr__(attr) 

  def do_405(self):
    self.send_response(405)
    self.send_header('Content-Length', 0)
    self.send_header('Allow', 'POST')
    self.end_headers()

  def do_POST(self):
    self.status = None

    try:
      config_objects = []

      if self.headers['Content-Type'] == 'application/json':
        if 'Content-Length' in self.headers:
          postdata = self.rfile.read(int(self.headers['Content-Length']))
          data = json.loads(postdata.decode('utf-8'))

          jsonschema.validate(instance=data, schema=schema)

          cloudvision = CloudVision(
            servers = [data['cv_server']],
            token = data['cv_token'],
            username = None,
            password = None,
            verify_certs = False
          )

          change_control = CVChangeControl(
            name = data.get('cv_change_control_name')
          )

          for device in data['devices']:
            device_object = CVDevice(hostname=device, serial_number=data['devices'][device].get('serial_number'))

            with tempfile.NamedTemporaryFile(delete=False) as tmp:
              tmp.write(base64.b64decode(data['devices'][device]['configlet'], validate=True))
              config_objects.append(CVEosConfig(file=tmp.name, device=device_object, configlet_name=f'AVD-{device}'))

          r = asyncio.run(deploy(cloudvision, config_objects, change_control, delete_workspace=data.get('cv_delete_workspace')))

          if r.failed:
            self.status = 'error'
            r.errors = [str(error) for error in r.errors]
            response = { 'status': 'error', 'errors': dataclasses.asdict(r)['errors'] }

          else:
            self.status = 'ok'
            if r.workspace.change_control_id is not None:
              response = { 'status': 'ok', 'change_control': r.change_control.name }
            else:
              response = { 'status': 'ok' }
      
          r = ['text/plain', 200, json.dumps(response, indent=2)]

        else:
          r = ['text/plain', 400, None]

      else:
        r = ['text/plain', 415, None]

    except jsonschema.ValidationError as e:
      response = { 'status': 'error', 'errors': [f'{type(e).__name__}: {e.message}'] }
      r = ['text/plain', 200, json.dumps(response, indent=2)]

    except Exception as e:
      response = { 'status': 'error', 'errors': [f'{type(e).__name__}: {e}'] }
      r = ['text/plain', 200, json.dumps(response, indent=2)]

    finally:
      for config_object in config_objects:
        os.remove(config_object.file)

    self.send_response(r[1])

    if r[2] is not None:
      self.send_header('Content-Type', r[0])
      self.send_header('Content-Length', len(r[2]))
    else:
      self.send_header('Content-Length', 0)

    self.end_headers()

    if r[2] is not None:
      self.wfile.write(r[2].encode('utf-8'))

class CVProxyThread(threading.Thread):
  def __init__(self, s, args):
    threading.Thread.__init__(self)
    self.s = s
    self.args = args
    self.daemon = True
    self.start()

  def run(self):
    httpd = HTTPServer((self.args.l, self.args.p), CVProxyRequest, False)
    httpd.socket = self.s
    httpd.server_bind = self.server_close = lambda self: None
    httpd.RequestHandlerClass.args = self.args
    httpd.serve_forever()

def log(t):
  timestamp = datetime.datetime.now().strftime('%b %d %H:%M:%S.%f')[:19]

  with llock:
    if os.getenv('JOURNAL_STREAM'):
      print(re.sub(r'\033\[(?:1;[0-9][0-9]|0)m', '', t))
    else:
      print(f'[{timestamp}] {t}')
  
def main(flag=[0], n_threads=4):
  try:
    if not os.getenv('JOURNAL_STREAM'):
      print(f'CVProxy v{__version__} - CloudVision Proxy')
      print('Copyright (c) 2026 Chris Mason <chris@netnix.org>\n')

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-s', action='store_true', required=True)
    parser.add_argument('-l', metavar='<address>', default='127.0.0.1', type=str)
    parser.add_argument('-p', metavar='<port>', default=8080, type=int)
    parser.add_argument('-xff', action='store_true', default=False)
    args = parser.parse_args()

    def signal_handler(*args):
      flag[0] = 2

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    log(f'Starting CVProxy (PID is {os.getpid()}) on http://{args.l}:{args.p}...')

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.l, args.p))
    s.listen()

    flag[0] = 1

    for i in range(n_threads):
      CVProxyThread(s, args)

    while flag[0] < 2:
      time.sleep(0.1)

    log('Terminating CVProxy...')

  except Exception as e:
    tb = e.__traceback__
    stack = []

    while tb is not None:
      stack.append([tb.tb_frame.f_code.co_filename, tb.tb_frame.f_code.co_name, tb.tb_lineno])
      tb = tb.tb_next

    print(f'Error[{os.path.basename(stack[0][0])}:{stack[0][2]}]: {type(e).__name__}: {e}', file=sys.stderr)

  finally:
    if flag[0] > 0:
      s.close()


if __name__ == '__main__':
  main() 
