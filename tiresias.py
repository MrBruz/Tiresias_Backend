#!/usr/bin/python3
# import all the required modules
__author__="Footsiefat"
__date__ ="$Sep 19, 2020$"

import curses
from   threading import Thread
from   optparse  import OptionParser
import time,os,subprocess,math
import socket,select,random,sys, rsa
import tempfile
import base64
import time
import socket
import threading
import string
import hashlib
import datetime
import os.path
from os import path
from cryptography.fernet import Fernet

messages = []
messagestosend = {}
messagesreceived = {}
rqstamnt = 100
nodes = {}
nodeIps = {}
threads = []
maxNodes = 256
maxNodes2 = maxNodes / 4
ourId = ''
ourKey = ''
initialisationDone = False
#from tkinter import font
#from tkinter import ttk

# import all functions /
# everthing from chat.py file
#from chat import *

minimum_message_len=16384

# Network-related variables
tor_server='127.0.0.1'

# Used if can't load it from configuration
tor_server_control_port=9051   # 9051                TBB / TOR
tor_server_socks_port=9050     # 9050
########################################################################################################  adjust this if you want
hidden_service_interface='127.0.0.1'
hidden_service_port=2124

## Time "noise". Increase this value in dire situations
clientRandomWait=1   # Random wait before sending messages
clientRandomNoise=10 # Random wait before sending the "noise message" to the server
serverRandomWait=1   # Random wait before sending messages

counter = 1

torMode = True
debugLevel = True


onionaddr = ""

#torMode = False

## Tor stem glue class

class torStem():
        def connect(self,addr='127.0.0.1',cport=9051):
                global onionaddr

                debug("[I] Connecting to TOR via Stem library")
                # Load Stem lib
                try:
                        from stem.control import Controller
                except:
                        debug("[E] Cannot load stem module.")
                        debug("[E] Try installing python-stem with the package manager of your distro ('pacman' or whatever)")
                        exit(0)
                # Connect to TOR
                self.controller = Controller.from_port(address=addr,port=cport)
                self.controller.authenticate()  # provide the password here if you set one

                bytes_read = self.controller.get_info("traffic/read")
                bytes_written = self.controller.get_info("traffic/written")

                debug("[I] Tor relay is alive. %s bytes read, %s bytes written." % (bytes_read, bytes_written))
                debug("[C] Tor Version: %s" % str(self.controller.get_version()))
                # Get socks port
                try:
                        self.SocksPort=self.controller.get_conf("SocksPort")
                        if self.SocksPort==None:
                                self.SocksPort=9050
                        else:   self.SocksPort=int(self.SocksPort)
                        debug("[C] Socks port is: %d" % self.SocksPort)
                except:
                        debug("[E] Failed to get Socks port, trying 127.0.0.1:9050...")
                        self.SocksPort=9050
                        pass


                # Add hidden service  ----------------------------------------------- error fixed now in 2016
                debug("[I] Adding hidden service.  Hit CTRL-C to stop server afterwards.  Please wait one minute until hidden service is ready.")

                self.hostname = self.controller.create_ephemeral_hidden_service({hidden_service_port: '%s:%d' % (hidden_service_interface, hidden_service_port)}, await_publication = True).service_id + '.onion'
                onionaddr = self.hostname
                debug("[C] Hostname is %s" % self.hostname)



        def disconnect(self):
          # Remove hidden service
          debug("[I] Removing hidden service and shutting down torIRC.")

          self.controller.remove_ephemeral_hidden_service(self.hostname.replace('.onion', ''))


def connectTimer():
  threading.Timer(60.0, connectTimer).start()
  #print("<UPDATING CONNECTION TIME> " + str(round(time.time())))
  firebase.put('/contacts/' + hashedUid, 'connecttime', round(time.time()))

def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))


def genRandomString(chars):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=chars))


## print Mode (Server prints to stdout, client do not)
STDoutprint=False

# Add padding to a message up to minimum_message_len
def addpadding(message):
        if len(message)<minimum_message_len:
                message+=chr(0)
                for i in range(minimum_message_len-len(message)):
                        message+=chr(random.randint(ord('a'),ord('z')))
        return message.encode()


## Return sanitized version of input string
def sanitize(string):
        out=""
        for c in string:
                if (ord(c)==0): break # char(0) marks start of padding
                if (ord(c)>=0x20) and (ord(c)<0x80):
                        out+=c
        return out

def getRandomNodes(id,nodesInternal,nodeDepth):
        global maxNodes
        global maxNodes2
        global nodeIps
        filteredNodes = []
        otherNodes = []
        filterId = id[:nodeDepth]
        for nodes in nodesInternal:
            if nodes.startswith(filterId):
                filteredNodes.append(nodes)
            else:
                otherNodes.append(nodes)
        debug(filteredNodes,otherNodes)
        returnNodes = ""
        if not len(filteredNodes) > maxNodes2:
            counter = 1
            for i in filteredNodes:
                if counter == 1:
                    returnNodes = i + '§' + nodeIps[i]
                else:
                    returnNodes = returnNodes + '-' + i + '§' + nodeIps[i]
                counter = counter + 1
        else:
            for x in range(maxNodes2):
                grabNode = filteredNodes.pop(random.randint(0, len(filteredNodes) - 1))
                if x == 0:
                    returnNodes = returnNodes + grabNode + '§' + nodeIps[grabNode]
                else:
                    returnNodes = returnNodes + '-' + filteredNodes.pop(random.randint(0, len(filteredNodes) - 1))
        returnNodes2 = ""
        if not len(otherNodes) > maxNodes:
            counter = 1
            for i in otherNodes:
                if counter == 1:
                    returnNodes2 = i + nodeIps[i]
                else:
                    returnNodes2 = returnNodes2 + '-' + i + '§' + nodeIps[i]
                counter = counter + 1
        else:
            for x in range(maxNodes):
                grabNode2 = otherNodes.pop(random.randint(0, len(otherNodes) - 1))
                if x == 0:
                    returnNodes2 = returnNodes2 + grabNode + '§' + nodeIps[grabNode]
                else:
                    returnNodes2 = returnNodes2 + '-' + grabNode + '§' + nodeIps[grabNode]
        return returnNodes + '§§' + returnNodes2

## print function

def addToMsgsSend(ip,messages):
    global messagestosend
    if not messagestosend.get(ip) or not len(messagestosend.get(ip)) > 0:
       messagestosend[ip] = []
    messagestosend[ip].append(messages)


def addToMsgsRecv(ip,messages):
    global messagesreceived
    if not messagesreceived.get(ip) or not len(messagesreceived.get(ip)) > 0:
       messagesreceived[ip] = []
    messagesreceived[ip].append(messages)

def remove_prefix(text, prefix):
    if text.startswith(prefix):
        return text[len(prefix):]
    return text

def locateNode(nodeId):
    global numNodes
    global nodeIps
    global maxNodesSvr
    global foundNodes
    if not nodeId in list(nodeIps.keys()):
        nodeDepth = math.floor(int(numNodes) / maxNodesSvr)
        availableNodes = [x for x in list(nodeIps.keys()) if x.startswith(nodeId[:nodeDepth])]
        rqstmsg = '§DO-YOU-KNOW§' + nodeId
        addToMsgsSend(nodeIps[availableNodes.pop(random.randint(0, len(availableNodes) - 1))],rqstmsg.encode())
        while not foundNodes.get(nodeId):
            time.sleep(1)
        return foundNodes.pop(nodeId)
    else:
        return nodeIps[nodeId]

def recvall(sock):
    BUFF_SIZE = 4096 # 4 KiB
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) < BUFF_SIZE:
            # either 0 or end of data
            break
    return data

def backupNodesToFile(id,ip,file):
    if path.exists(file):
        f = open(file, "r")
        pfRead = list(filter(None, f.read().split('\n')))
        f.close()
        if not any(item.startswith(id + '§') for item in pfRead):
            f = open(file, "a")
            f.write(id + '§' + ip + '\n')
        else:
            data = ''
            for x in pfRead:
                if x.startswith(id + '§'):
                    data = data + x.replace(x.split(id + '§')[1],ip) + '\n'
                else:
                    data = data + x + '\n'
            f = open(file, "w")
            f.write(data)
    else:
        f = open(file, "a")
        f.write(id + '§' + ip + '\n')

def debug(text):
    global debugLevel
    if debugLevel:
        print(text)

### Server class
# Contains the server socket listener/writer

class Server():
        # Server roster dictionary: nick->timestamp
        serverRoster={}

        ## List of message queues to send to clients
        servermsgs=[]

        ## channel name
        channelname=""

        ## Eliminate all nicks more than a day old
        def serverRosterCleanThread(self):
                while True:
                        time.sleep(10)
                        current=time.time()
                        waittime = random.randint(60*60*10,60*60*36)         # 10 hours to 1.5 days
                        for b in self.serverRoster:
                                if current-self.serverRoster[b]>waittime:    # Idle for more than the time limit
                                        self.serverRoster.pop(b)             # eliminate nick
                                        waittime = random.randint(60*60*10,60*60*36)

        ## Thread attending a single client
        def serverThread(self,conn,addr,msg,nick):
                global messagestosend
                global nodes
                global maxNodes
                global maxNodesSvr
                global numNodes
                global foundNodes
                global ourId
                global ourKey
                global initialisationDone
                debug("[I] (ServerThread): Received connection from: " + str(addr))
                conn.setblocking(0)
                randomwait=random.randint(1,serverRandomWait)
                start = time.time()
                received = b''
                counter = 1
                ip = addr[0]
                while (True):
                        try:
                                #time.sleep(0.05)
                                ready = select.select([conn], [], [], 1.0)
                                if ready[0]:
                                        data=recvall(conn)
                                        if len(data)==0: continue
                                        try:
                                            dataDecoded = data.decode()
                                        except:
                                            debug("[E] Error decoding packet")
                                        else:
                                            if dataDecoded.startswith('§REQUEST-IDENTITY§') and dataDecoded.count('§') == 2:
                                                    debug('[I] ' + addr[0] + ' is requesting an identity from us.')
                                                    id = genRandomString(16)
                                                    key = genRandomString(32)
                                                    msg = id + '-' + key
                                                    nodes[id] = key
                                                    nodeIps[id] = ip
                                                    f = open("ts_keys.txt", "a")
                                                    f.write(id + '§' + key + '\n')
                                                    f.close()
                                                    addToMsgsSend(ip,msg.encode())
                                            elif dataDecoded.startswith('§HELLO§') and dataDecoded.count('§') == 3:
                                                    processedData = remove_prefix(dataDecoded,'§HELLO§')
                                                    ip = processedData.split('§')[0]
                                                    id = processedData.split('§')[1]
                                                    debug('[I] ' + 'Node, ' + id + ' said hello from ' + ip)
                                                    nodeIps[id] = ip
                                                    backupNodesToFile(id,ip,'ts_ids.txt')
                                            elif dataDecoded.startswith('§GIVE-SVR-VARS§') and dataDecoded.count('§') == 2:
                                                    msg = '§HELLO-SERVER§' + str(len(nodes)) + '§' + str(maxNodes)
                                                    addToMsgsSend(ip,msg.encode())
                                            elif dataDecoded.startswith('§HELLO-IP§') and dataDecoded.count('§') == 2:
                                                    ip = dataDecoded.split('§')[2]
                                                    debug('[I] ' + 'A node said hello from ' + ip)
                                            elif dataDecoded.startswith('§HELLO-SERVER§') and dataDecoded.count('§') == 3:
                                                    numNodes = int(remove_prefix(dataDecoded,'§HELLO-SERVER§').split('§')[0])
                                                    maxNodesSvr = int(remove_prefix(dataDecoded,'§HELLO-SERVER§').split('§')[1])
                                                    initialisationDone = True
                                            elif dataDecoded.startswith('§DO-YOU-KNOW§') and dataDecoded.count('§') == 2:
                                                    nodeId = remove_prefix(dataDecoded,'§DO-YOU-KNOW§')
                                                    if nodeId in list(nodeIps.keys()):
                                                        msg = '§FOUND-THEM§' + nodeIps[nodeId] + '§' + nodeId
                                                    else:
                                                        msg = '§COULDNT-FIND-NODE§'
                                                    addToMsgsSend(ip,msg.encode())
                                            elif dataDecoded.startswith('§FOUND-THEM§') and dataDecoded.count('§') == 3:
                                                    foundNodes[remove_prefix(dataDecoded,'§FOUND-THEM§').split('§')[1]] = remove_prefix(dataDecoded,'§FOUND-THEM§').split('§')[0]
                                            elif dataDecoded.startswith('§REQUEST-CLUSTER-NODES§') and dataDecoded.count('§') == 3:
                                                    debug('[I] ' + ip + ' is requesting sacrfices to connect to.')
                                                    clusterDepth = math.floor(len(nodes) / maxNodes)
                                                    randomNodes = getRandomNodes(dataDecoded.split('§')[2],list(nodeIps.keys()).copy(),clusterDepth)
                                                    msg = '§NODES§' + randomNodes
                                                    addToMsgsSend(ip,msg.encode())
                                            elif dataDecoded.count('§') == 0 and dataDecoded.count('-') == 1:
                                                    ourId = dataDecoded.split('-')[0]
                                                    ourKey = dataDecoded.split('-')[1]
                                                    debug('[I] ' + "We have received an idenity from " + ip + " id:" + dataDecoded.split('-')[0] + " key:" + dataDecoded.split('-')[1])
                                            elif dataDecoded.startswith('§NODES§'):
                                                    processed = remove_prefix(dataDecoded,'§NODES§')
                                                    receivedNodes = list(filter(None, processed.split('§§')[0].split('-') + processed.split('§§')[1].split('-')))
                                                    for x in receivedNodes: #X Gon' Give It to Ya
                                                        nodeIps[x.split('§')[0]] = x.split('§')[1]
                                                    debug('[I] ' + "We have received " + str(len(receivedNodes)) + " nodes from " + addr[0])
                                            elif dataDecoded.startswith('§GIVE-FERNET-KEY§'):
                                                    fernetKey = Fernet.generate_key()
                                                    pub_key = remove_prefix(dataDecoded,'§GIVE-FERNET-KEY§').split(" ")
                                                    pub_key_2 = rsa.PublicKey(n=int(pub_key[0]), e=int(pub_key[1]))
                                                    msg = b'§HERE-FERNET-KEY§' + rsa.encrypt(message, pub_key_2)
                                                    addToMsgsSend(ip,msg)
                                            elif dataDecoded.startswith('§HERE-FERNET-KEY§'):
                                                    fernetKey = remove_prefix(dataDecoded,'§HERE-FERNET-KEY§')
                                            elif dataDecoded.startswith('§MSG§'):
                                                    msg = remove_prefix(dataDecoded,'§MSG§')
                                                    debug('[I] ' + addr[0] + ' ' + msg)
                                                    addToMsgsRecv(addr[0],msg)
                                            else:
                                                    debug("[I] <RECEIVED> " + dataDecoded)
                                            messages.append(dataDecoded)


                        except:
                                self.servermsgs.remove(msg)
                                conn.close()
                                debug('[I] exiting...')
                                raise

        ## Server main thread
        def serverMain(self):
                global torMode
                global STDOutprint
                STDOutprint=True
                if torMode:
                    # Connects to TOR and create hidden service
                    self.ts=torStem()
                    try:
                            self.ts.connect(tor_server,tor_server_control_port)
                    except Exception as e:
                            debug(("[E] %s" % e))
                            debug("[E] Check if the control port is activated in /etc/tor/torrc")
                            debug("[E] Try to run as the same user as tor, i.e.   sudo -u debian-tor ./tiresias.py  (maybe useful or not) ")
                            exit(0)
                # Start server socket
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((hidden_service_interface,hidden_service_port))
                debug('[I] Server now Active')
                s.listen(5)
                # Create server roster cleanup thread
                t = Thread(target=self.serverRosterCleanThread, args=())
                t.daemon = True
                t.start()
                while True:
                        try:
                                conn,addr = s.accept()
                                cmsg=[]
                                nick="anon_%d" % random.randint(0,10000)
                                self.servermsgs.append(cmsg)
                                t = Thread(target=self.serverThread, args=(conn,addr,cmsg,nick))
                                t.daemon = True
                                t.start()
                        except KeyboardInterrupt:
                                self.ts.disconnect()
                                debug("[I] (Main Server Thread): Exiting")
                                exit(0)
                        except:
                                pass


# Client connection thread
def clientConnectionThread(ServerOnionURL):
        global roster
        global threads
        global messagestosend
        global torMode
        # Try to load Socksipy
        import socks
        while(True):

                        debug(("[I] Trying to connect to %s:%d" % (ServerOnionURL,hidden_service_port)))
                        ## Connects to TOR via Socks
                        s=socks.socksocket(socket.AF_INET,socket.SOCK_STREAM)
                        if torMode:
                            s.setproxy(socks.PROXY_TYPE_SOCKS5,tor_server,tor_server_socks_port)
                        s.settimeout(100)
                        s.connect((ServerOnionURL,hidden_service_port))
                        s.setblocking(0)
                        debug(("[I] clientConnection: Connected to %s" % ServerOnionURL))
                        randomwait=random.randint(1,clientRandomWait)
                        counter = 1
                        lastPacket = 99999999999
                        while(not lastPacket + 60 < time.time()):
                                time.sleep(1)
                                ready = select.select([s], [], [], 1.0)
                                # We need to send a message
                                if messagestosend.get(ServerOnionURL):
                                    if len(messagestosend.get(ServerOnionURL)) > 0:
                                        debug('[I] <SENDING> ' + messagestosend.get(ServerOnionURL)[0].decode())
                                        msgs = messagestosend.get(ServerOnionURL).pop(0)
                                        if len(msgs)>0:
                                            #m = addpadding(msgs)
                                            lastPacket = time.time()
                                            if not os.name == 'nt' and len(msgs) > 1048576: #Patch for linux, 'BlockingIOError: [Errno 11] Resource temporarily unavailable' if file size over 1mb, so this splits it into chunks.
                                                msgsSplit = list(chunkstring(msgs,1048576))
                                                for i in msgsSplit:
                                                    s.sendall(i)
                                                    debug("sent chunk")
                                                    time.sleep(0.1)
                                            else:
                                                s.sendall(msgs)
                                        randomwait=random.randint(1,clientRandomWait)
                                counter = counter + 1
                        debug("[I] Timeout (60 seconds since last packet sent.), on connection to " + ServerOnionURL)
                        threads.remove(ServerOnionURL)
                        break
        s.close()


## Client main procedure
def clientMain(ServerOnionURL):
        global cmdline
        global inspoint
        global pagepoint
        global width,height

        ## Message queue to send to server
        clientConnectionThread(ServerOnionURL)



# Client
# Init/deinit curses
def Client(ServerOnionURL):
  global stdscr
  global STDOutprint
  STDOutprint=False


  clientMain(ServerOnionURL)
  exit(0)

def AutoGenClientThreads():
    global threads
    global messagestosend
    while True:
        for item in list(messagestosend):
            if not item in threads and len(messagestosend.get(item)) > 0:
                threads.append(item)
                thread = Thread(target = Client,args=[item])
                thread.start()
        time.sleep(0.1)

if len(sys.argv) > 1:
    if sys.argv[1] == "-s":
        type = "SERVER"
    elif sys.argv[1] == "-c":
        type = "CLIENT"
    else:
        type = "OTHER"
else:
    type = "OTHER"


debug("[I] Running in " + type + " mode")

if type == "CLIENT" or type == "CLIENT-REQUEST-NODES" or type == "OTHER":
    inputaddr = '6hoxnaskwlm4bkh5jtqles2sdjx3sqo4h7lubhmtfidtavchqoemsaad.onion'
    #inputaddr = input("Enter ip: ")
    if inputaddr == '':
        type = "NONE"


'''
if input("[Q] Hey boss, we using TOR? ").lower().startswith('y'):
    torMode = True
'''

thread = Thread(target = AutoGenClientThreads)
thread.start()

thread = Thread(target = Server().serverMain)
thread.start()

while onionaddr == "":
    time.sleep(0.2)

if type != "SERVER":
    if path.exists('ts_pf.txt'):
        f = open("ts_pf.txt", "r")
        pfRead = f.read().strip()
        f.close()
        ourId = pfRead.split('§')[0]
        ourKey = pfRead.split('§')[1]
        rqstmsg = '§HELLO§' + onionaddr + '§' + ourId
        addToMsgsSend(inputaddr,rqstmsg.encode())
    else:
        rqstmsg = '§HELLO-IP§' + onionaddr
        addToMsgsSend(inputaddr,rqstmsg.encode())
        rqstmsg = '§REQUEST-IDENTITY§'
        addToMsgsSend(inputaddr,rqstmsg.encode())
        f = open("ts_pf.txt", "w")
        while ourId == '' or ourKey == '':
            time.sleep(0.5)
        f.write(ourId + '§' + ourKey)
        f.close()
        rqstmsg = '§HELLO§' + onionaddr + '§' + ourId
        addToMsgsSend(inputaddr,rqstmsg.encode())
else:
    if path.exists('ts_keys.txt'):
        f = open("ts_keys.txt", "r")
        pfRead = f.read().split('\n')
        for x in pfRead:
            if x.strip() != '':
                theirId = x.strip().split('§')[0]
                theirKey = x.strip().split('§')[1]
                nodes[theirId] = theirKey
        f.close()

if path.exists('ts_ids.txt'):
    f = open("ts_ids.txt","r")
    pfRead = f.read().split('\n')
    for x in pfRead:
        if x.strip() != '':
            theirId = x.strip().split('§')[0]
            theirIp = x.strip().split('§')[1]
            nodeIps[theirId] = theirIp
    f.close()

rqstmsg = '§REQUEST-CLUSTER-NODES§' + ourId + '§'
addToMsgsSend(inputaddr,rqstmsg.encode())
rqstmsg = '§GIVE-SVR-VARS§'
addToMsgsSend(inputaddr,rqstmsg.encode())

while not initialisationDone:
    time.sleep(0.2)

def startEncryption(ip):
    public_key, private_key = rsa.newkeys(2048)
    rqstmsg = '§GIVE-FERNET-KEY§' + str(public_key['n']) + " " + str(public_key['e'])
    addToMsgsSend(ip,rqstmsg.encode())


rqstmsg = '§MSG§' + 'test message 123...'
addToMsgsSend(locateNode('fElcJWaSLF0vqeTO'),rqstmsg.encode())
