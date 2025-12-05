"""
CLima =  this is called by CILOGIN to get a set of claims as if they came
form keyclaoak.  this list is then presented to the syste which hels them against
keyclak truth?   I don;t thisn I really grok if.
"""


from http.server import BaseHTTPRequestHandler, HTTPServer


body = '''
{
          "sub": "http://cilogon.org/serverE/users/337266",
          "email_list": [
            "dpetravick@gmail.com"
          ],
          "iss": "https://cilogon.org",
          "vo_person_id": "SCiMMA1000005",
          "is_member_of": [
            "CO:members:all",
            "SCiMMA Institute Members",
            "CO:members:active",
            "CO:COU:SCiMMA DevOps:members:active",
            "SCiMMA Institute Active Members",
            "kafkaUsers",
            "/Hopskotch Users"
          ],
          "email": "dpetravick@gmail.com",
          "vo_display_name": "dpetravick@gmail.com"
        }
'''

class CustomHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Set custom headers
        self.send_response(200)
        self.send_header('Content-Type:',' application/json;charset=UTF-8')
        self.send_header('Connection:','close')
        self.end_headers()

        # Static response body
        print ("WEB WEB WEB WEB WEB\n", body, "\n WEB WEB WEB WEB")
        
        response_body = body
        self.wfile.write(response_body.encode('utf-8'))

webServer = HTTPServer(('localhost', 8001), CustomHandler)
print('Server started')
webServer.serve_forever()
"""
def run(server_class=HTTPServer, handler_class=CustomHandler, port=8081)
    server_address = ('127.0.0.1', port)
    httpd = server_class(server_address, handler_class)
    print(f"Serving on port {port}...")
    httpd.serve_forever()

if __name__ == '__main__':
    run()
"""
