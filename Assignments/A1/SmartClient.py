#!/usr/bin/python3

# Not allowed to use any big boy libraries

import socket
import sys
import re
import ssl
DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443
HTTP_SUPPORTING_CODES = [2, 3]


def main():
    """
    [summary]
        For this assignment I will be following the algorithm recommended in tutorail 2 but with a few tweaks.
        1. Authenticate validity of URI with regular expression(look at getUserInput for specifics)
        2. Parse URI input either from argument via CLI or via input prompt
        3. Use Parsed URI data to connect to server using socket 
        4. Send Http request to server, tcp request
        5. Receive Http request from server
        6. Process data received from server
        7. Depending on data go to step 4 with a new request or end code 

        p.s. hopefully isn't too potato code. 
        cheers, 

        Ryan Barclay
    """

    cookieMasterList = []
    cookieJar = []
    http11Support = False
    httpsSupport = False
    http2Support = False

    inputVar = getUserInput()
    inputParsed = parseUserInput(inputVar)
    # print(inputVar)

    #HTTPS
    dataHTTPS = httpsTest(inputParsed)
    if dataHTTPS != "":
        httpsSupport, cookieJar = processResponce(dataHTTPS)

        #Deal with cookies
        if cookieJar:
            for cookie in cookieJar:
                cookieMasterList.append(cookie)
        
        #check for Http2
        http2Support = http2Test(inputParsed)

        
    # print(cookieMasterList)

    #HTTP1.1
    dataHTTP = http11Test(inputParsed)
    decodedDataHTTP = dataHTTP.decode("utf8")
    http11Support = processResponce(decodedDataHTTP)
    # print(str(dataHTTP, 'utf-8'))
    #Deal with cookies
    if cookieJar:
        for cookie in cookieJar:
            cookieMasterList.append(cookie)
    
    # print(cookieMasterList)

    # context = ssl.SSLContext with a TLS protocol 
    # context.wrap_socket

    print("website: "+ inputParsed[1])
    if httpsSupport: 
        print("1. Supports of HTTPS: yes")
    else:
        print("1. Supports of HTTPS: no")

    if http11Support:
        print("2. Supports http1.1: yes")
    else:
        print("2. Supports http1.1: no")
    
    if http2Support:
        print("3. Supports http2: yes")
    else:
        print("3. Supports http2: no")
    
    print("4. List of {} Cookies:".format(len(cookieMasterList)))
    for cookie in cookieMasterList:
        print(*cookie, sep = ", ")



def http11Test(userInputFormated):
    

    # socket creation
    try:  
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # print ("Socket successfully created")
    except socket.error as err:
        print ("socket creation failed with error %s" %(err))

    # TCP connection
    try:
        s.connect((userInputFormated[1], DEFAULT_HTTP_PORT))  # Connect
    except:
        print("connection creation failed with error %s" %(err))

    # Format request
    # if userInputFormated[2]:
    #     request = "GET http://" + userInputFormated[1] + "/" + userInputFormated[2] + " HTTP/1.1\r\n\r\n"
    # else:
    #     request = "GET http://" + userInputFormated[1] + " HTTP/1.1\r\n\r\n"
    #     # request = "GET / HTTP/1.1\r\n\r\n"
    request = "GET /"  + " HTTP/1.1\r\nHOST:"+ userInputFormated[1] +"\r\nCONNECTION:Keep-Alive\r\n\r\n"

    # Send Request
    print("--Request begin--")
    print (request)
    print("--Request end--")
    s.sendall(request.encode('utf-8'))
    data = s.recv(10000)  # Get response
    s.close()
    return data

def http2Test(userInputFormated):

    # Ssl Prep
    sslInfo = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2)
    sslInfo.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
    sslInfo.set_alpn_protocols(['h2', 'HTTP/1.1'])
    sslInfo.options |= ssl.OP_NO_COMPRESSION 

    # Set up some variables
    # if userInputFormated[2]:
    #     request = "GET http://" + userInputFormated[1] + "/" + userInputFormated[2] + " HTTP/1.1\r\nCONNECTION:Keep-Alive\r\n\r\n"
    # else:
    #     request = "GET http://" + userInputFormated[1] + " HTTP/1.1\r\nHOST:" + userInputFormated[1] + "\r\nCONNECTION:Keep-Alive\r\n\r\n"
    # request = "GET /"  + " HTTP/1.1\r\nHOST:"+ userInputFormated[1] +"\r\nCONNECTION:Keep-Alive\r\n\r\n"
        # request = "GET / HTTP/1.1\r\n\r\n"\
    # encodeMessage = request.encode(encoding="UTF-8", errors="ignore")


    # Create socket
    try:  
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # print ("Socket successfully created")
    except socket.error as err:
        print ("socket creation failed with error %s" %(err))
    
    # connect to host
    try:
        soc.connect((userInputFormated[1], DEFAULT_HTTPS_PORT))  # Connect
    except:
        print("connection creation failed with error %s" %(err))

    try:
        secureSocket = sslInfo.wrap_socket(soc, server_hostname=userInputFormated[1])
    except:
        print("wrap_socket failed with error %s" %(err))

    try:
        negotiated_protocol = secureSocket.selected_alpn_protocol()
    except:
        print("making negotiated_protocol failed with error %s" %(err))
    
    if negotiated_protocol is None:
        return ""
    else:
        return True



def httpsTest(userInputFormated):

    # Ssl Prep
    sslInfo = ssl.SSLContext(protocol=ssl.PROTOCOL_TLSv1_2)
    sslInfo.set_alpn_protocols(["HTTP/1.1"])
    sslInfo.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20")
    sslInfo.options |= ssl.OP_NO_COMPRESSION 

    # Set up some variables
    # if userInputFormated[2]:
    #     request = "GET http://" + userInputFormated[1] + "/" + userInputFormated[2] + " HTTP/1.1\r\nCONNECTION:Keep-Alive\r\n\r\n"
    # else:
    #     request = "GET http://" + userInputFormated[1] + " HTTP/1.1\r\nHOST:" + userInputFormated[1] + "\r\nCONNECTION:Keep-Alive\r\n\r\n"
    request = "GET /"  + " HTTP/1.1\r\nHOST:"+ userInputFormated[1] +"\r\nCONNECTION:Keep-Alive\r\n\r\n"
        # request = "GET / HTTP/1.1\r\n\r\n"\
    encodeMessage = request.encode(encoding="UTF-8", errors="ignore")


    # Create socket
    try:  
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # print ("Socket successfully created")
    except socket.error as err:
        print ("socket creation failed with error %s" %(err))

    # Wrap in ssl layer
    try:    
        sslSoc = sslInfo.wrap_socket(soc,server_hostname=userInputFormated[1])
    except:
        print("Could not wrap the socket inside of the HTTPS")
        return ""
    
    # Try and connect 
    try:
        sslSoc.connect((userInputFormated[1], DEFAULT_HTTPS_PORT))
        print("--Request begin--")
        print(request)
        print("--Request end--")
        sslSoc.sendall(encodeMessage)
        print("HTTP request sent, awaiting response...\n")
        data = sslSoc.recv(10000)
        data = data.decode(errors="ignore")
        sslSoc.close()
        return data
    except socket.timeout:
        print("HTTPS Timed out")
        return ""
    except socket.gaierror:
        print("HTTPS Invalid URN/Hostname")
        return ""
    except OSError:
        print("HTTPS OSError")
        return ""

def processResponce(data):
    cookieList = []

    startBody = data.find("\r\n\r\n")
    headData = data[:startBody]
    bodyData = data[startBody+4:]
    
    print("---Response header ---")
    print(headData+"\n")
    print("---Response body ---")
    print(bodyData+"\n")

    # Now we look for Code to see if it is good
    headDataList = convert(headData)
    firstLine = headDataList[0]
    code = firstLine.split()
    # print(code[1][0])
    codeType = int(code[1][0])
    if codeType in HTTP_SUPPORTING_CODES:
        # it supports 
        isSupported = True
    else:
        isSupported = False

    # cookie hunting time
    # print("debug")
    for line in headDataList:
        if line.startswith("Set-Cookie:"):
            cookie = []
            # print("cookie found")
            cookieStart = line[12:]
            cookieStart = cookieStart.split("; ")
            for item in cookieStart:
                if "=" in item:
                    cookieElement = item.split("=")
                    # print(cookieElement)
                    if cookie == []:
                        # Name
                        cookieElement[0] = "cookie name: "+cookieElement[0]
                        cookie.append(cookieElement[0])

                    if "expires" in cookieElement[0]:
                        cookieElement[0]= cookieElement[0] +":"
                        cookie.append(' '.join(cookieElement))
                    elif "Expires" in cookieElement[0]:
                        cookieElement[0]= cookieElement[0] +":"
                        cookieElement=' '.join(cookieElement)
                        # print(cookieElement+ " HERE")
                        cookie.append(cookieElement)

                    if "domain" in cookieElement[0]:
                        cookieElement[0]= cookieElement[0] +":"
                        cookie.append(' '.join(cookieElement))
                    elif "Domain" in cookieElement[0]:
                        cookieElement[0]= cookieElement[0] +":"
                        cookieElement=' '.join(cookieElement)
                        # print(cookieElement+ " HERE")
                        cookie.append(cookieElement)
            cookieList.append(cookie)
    # print(cookieList)
    return isSupported, cookieList





def getUserInput():
    """[summary]

    Returns:
        [type]: [description]
    """
    uriPattern = r"^([\w\-\.\+]+(\:\/\/))?([\w\-\.])+((\:)[0-9]+)?([\w\-\/\?\#\&\;\.]*)?$"
    # valid url checker based from rules of resources linked at https://en.wikipedia.org/wiki/URL and format of protocol://host[:port]/filepath as stated in assign doc

    if(len(sys.argv) == 2):
        # Validate url based
        if(re.match(uriPattern, sys.argv[1])):
            # We are good because it matches
            # print("matches")
            pass
        else:
            print("Please be advised that URI entered is not a standard case, please confirm URI if any problems.\n")
        return sys.argv[1]
    elif(len(sys.argv) == 1):
        usrInput = input("No URI found as argument, please enter a URI:")
        if(usrInput is None):
            print("No URI detected after prompt, Exiting Program")
            sys.exit()
        else:
            return usrInput
    else:
        print("Too many argument")
        sys.exit()


def parseUserInput(uri):
    """[summary]

    Args:
        uri ([type]): [description]

    Returns:
        [type]: [description]
    """

    # protocol, host, port, filepath
    endProtocolIndex = uri.find("://")

    # protocol
    if endProtocolIndex == -1:
        # no protocol in this URN
        protocol = None
        uriItter = uri
    else:
        protocol = uri[:endProtocolIndex]
        uriItter = uri[endProtocolIndex+3:]
        # iterate through the uri and chop off the :// part so we don't have to worry about it

    # host
    startPort = uriItter.find(":")

    if startPort != -1:
        # if port is there we chop off the host part of the uri
        host = uriItter[:startPort]
        uriItter = uriItter[startPort:]
    else:
        # if port isn't in uri we look for a path in it
        filepathStart = uriItter.find("/")
        if filepathStart == -1:
            # there is no path or port
            host = uriItter
        else:
            # there is no port but there is a path, so we chop off the host part of it
            host = uriItter[:filepathStart]
            uriItter = uriItter[filepathStart:]

    # port
    startPort = uriItter.find(":")
    if startPort != -1:
        # there is a port
        filepathStart = uriItter.find("/")
        if filepathStart != -1:
            # there is a port and there is a path
            port = uriItter[startPort:filepathStart]
            uriItter = uriItter[filepathStart:]
        else:
            # there is a port and no path
            port = uriItter[startPort+1:]
            uriItter = uriItter[startPort+1:]
    else:
        port = None

    # path
    filepathStart = uriItter.find("/")
    if filepathStart != -1:
        # there is a path
        path = uriItter[filepathStart+1:]
    else:
        path = None
    output = [protocol, host, port, path]

    output = [(i or None) for i in output] 

    # print(output)
    return output

def convert(string): 
    li = string.splitlines()
    return li

if __name__ == '__main__':
    main()
