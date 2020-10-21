from enum import Enum
from utils import formattedArray, prependedLength

SERVER_NAME_EXTENSION = b'\0\0'


class Extension():

    def __init__(self, extension_type, data):
        self.extension_type = extension_type
        self.data = data
        
    def __bytes__(self):
        return self.extension_type + self.data


class ServerNameExtension(Extension):

    def __init__(self, hostnames: [bytes]):
        data = formattedArray(
            [b'\0'  # Indicates entry type is DNS Hostname
            + prependedLength(bytes(hostname, 'ascii', 'strict'), 2)
            for hostname in hostnames])
        super().__init__(SERVER_NAME_EXTENSION, data)
        

