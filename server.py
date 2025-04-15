# Authors:
# Richard Li (rl902)
# Wesley Zhou (wgz4)

import socket
import signal
import sys
import random

# Read a command line argument for the port where the server
# must run.
port = 8080
public_host = None  # This will override the host to use in the form action.
if len(sys.argv) > 1:
    port = int(sys.argv[1])
    if len(sys.argv) > 2:
        public_host = sys.argv[2]  # Optional: specify the public IP/hostname.
else:
    print("Using default port 8080")
hostname = socket.gethostname()

# Start a listening server socket on the port
sock = socket.socket()
sock.bind(('', port))
sock.listen(2)

### Contents of pages we will serve.
# Login form
login_form = """
   <form action = "http://%s" method = "post">
   Name: <input type = "text" name = "username">  <br/>
   Password: <input type = "text" name = "password" /> <br/>
   <input type = "submit" value = "Submit" />
   </form>
"""
# Default: Login page.
login_page = "<h1>Please login</h1>" + login_form
# Error page for bad credentials
bad_creds_page = "<h1>Bad user/pass! Try again</h1>" + login_form
# Successful logout
logout_page = "<h1>Logged out successfully</h1>" + login_form
# A part of the page that will be displayed after successful
# login or the presentation of a valid cookie
success_page = """
   <h1>Welcome!</h1>
   <form action="http://%s" method = "post">
   <input type = "hidden" name = "action" value = "logout" />
   <input type = "submit" value = "Click here to logout" />
   </form>
   <br/><br/>
   <h1>Your secret data is here:</h1>
"""

#### Helper functions
# Printing.
def print_value(tag, value):
    print("Here is the", tag)
    print("\"\"\"")
    print(value)
    print("\"\"\"")
    print()

# Signal handler for graceful exit
def sigint_handler(sig, frame):
    print('Finishing up by closing listening socket...')
    sock.close()
    sys.exit(0)
# Register the signal handler
signal.signal(signal.SIGINT, sigint_handler)

# TODO: put your application logic here!
# Read login credentials for all the users
# Read secret data of all the users

auth_map = {}     # username -> password
secrets_map = {}  # username -> secret

with open("passwords.txt", "r") as f:
    for line in f:
        line = line.strip()
        if not line: 
            continue
        user, pwd = line.split()
        auth_map[user] = pwd

with open("secrets.txt", "r") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        user, secret = line.split()
        secrets_map[user] = secret

# Dictionary mapping session tokens to the username that was successfully authenticated
session_map = {}  # token -> username

def parse_cookie(headers):
    cookie_line = None
    for h in headers.split('\r\n'):
        if h.lower().startswith("cookie:"):
            cookie_line = h
            break

    if not cookie_line:
        return None

    cookie_part = cookie_line.split(":", 1)[1].strip() 
    for part in cookie_part.split(";"):
        part = part.strip()
        if part.startswith("token="):
            return part.split("=", 1)[1]
    return None

def parse_post_body(body):
    post_dict = {}
    if not body:
        return post_dict

    fields = body.split('&')
    for kv in fields:
        if '=' in kv:
            key, val = kv.split('=', 1)
            post_dict[key] = val
    return post_dict

### Loop to accept incoming HTTP connections and respond.
while True:
    client, addr = sock.accept()
    req = client.recv(1024)

    # Let's pick the headers and entity body apart
    header_body = req.decode().split('\r\n\r\n')
    headers = header_body[0]
    body = '' if len(header_body) == 1 else header_body[1]
    print_value('headers', headers)
    print_value('entity body', body)

    # TODO: Put your application logic here!
    # Parse headers and body and perform various actions

    # OPTIONAL TODO:
    # Set up the port/hostname for the form's submit URL.
    # If you want POSTing to your server to
    # work even when the server and client are on different
    # machines, the form submit URL must reflect the `Host:`
    # header on the request.
    # Change the submit_hostport variable to reflect this.
    # This part is optional, and might even be fun.
    # By default, as set up below, POSTing the form will
    # always send the request to the domain name returned by
    # socket.gethostname().

    if public_host:
        submit_hostport = f"{public_host}:{port}"
    else:
        # Otherwise, use the Host header if available.
        host_header = None
        for line in headers.split('\r\n'):
            if line.lower().startswith("host:"):
                host_header = line.split(":", 1)[1].strip()
                break
        if host_header:
            submit_hostport = host_header
        else:
            submit_hostport = f"{hostname}:{port}"

    # Parse POST body and extract cookies
    fields = parse_post_body(body)
    token_from_cookie = parse_cookie(headers)

    # You need to set the variables:
    # (1) `html_content_to_send` => add the HTML content you'd
    # like to send to the client.
    # Right now, we just send the default login page.
    html_content_to_send = login_page % submit_hostport
    # But other possibilities exist, including
    # html_content_to_send = (success_page % submit_hostport) + <secret>
    # html_content_to_send = bad_creds_page % submit_hostport
    # html_content_to_send = logout_page % submit_hostport
    
    # (2) `headers_to_send` => add any additional headers
    # you'd like to send the client?
    # Right now, we don't send any extra headers.
    headers_to_send = ''

    # (E) Logout
    if fields.get("action") == "logout":
        html_content_to_send = logout_page % submit_hostport
        headers_to_send  = 'Set-Cookie: token=; expires=Thu, 01 Jan 1970 00:00:00 GMT\r\n'
        if token_from_cookie and token_from_cookie in session_map:
            del session_map[token_from_cookie]

    else:
        # (C) 
        if token_from_cookie and token_from_cookie in session_map:
            valid_user = session_map[token_from_cookie]
            user_secret = secrets_map.get(valid_user, "No secret found.")
            html_content_to_send = (success_page % submit_hostport) + user_secret

        # (D) 
        elif token_from_cookie and token_from_cookie not in session_map:
            html_content_to_send = bad_creds_page % submit_hostport

        # If no valid cookie is presented, process the username and password fields.
        else:
            if "username" in fields and "password" in fields:
                username = fields["username"]
                password = fields["password"]
                if username in auth_map and auth_map[username] == password:
                    user_secret = secrets_map.get(username, "No secret found.")
                    html_content_to_send = (success_page % submit_hostport) + user_secret
                    rand_val = random.getrandbits(64)
                    token_str = str(rand_val)
                    session_map[token_str] = username
                    headers_to_send = 'Set-Cookie: token=' + token_str + '\r\n'
                else:
                    html_content_to_send = bad_creds_page % submit_hostport
            else:
                if ("username" in fields and "password" not in fields) or \
                   ("password" in fields and "username" not in fields):
                    html_content_to_send = bad_creds_page % submit_hostport

    # Construct and send the final HTTP response.
    response  = 'HTTP/1.1 200 OK\r\n'
    response += headers_to_send
    response += 'Content-Type: text/html\r\n\r\n'
    response += html_content_to_send
    print_value('response', response)

    client.send(response.encode())
    client.close()

    print("Served one request/connection!\n")


# We will never actually get here.
# Close the listening socket
sock.close()
