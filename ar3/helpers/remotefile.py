'''
Modified from:
https://github.com/byt3bl33d3r/CrackMapExec/blob/master/cme/protocols/smb/remotefile.py
'''

from impacket.smb3structs import FILE_READ_DATA, FILE_WRITE_DATA

class RemoteFile:
    def __init__(self, smbConnection, fileName, share, access = FILE_READ_DATA | FILE_WRITE_DATA ):
        self.__smbConnection = smbConnection
        self.__share = share
        self.__access = access
        self.__fileName = fileName
        self.__tid = self.__smbConnection.connectTree(share)
        self.__fid = None
        self.__currentOffset = 0

    def create(self):
        self.__fid = self.__smbConnection.createFile(self.__tid, self.__fileName)

    def open(self):
        self.__fid = self.__smbConnection.openFile(self.__tid, self.__fileName, desiredAccess= self.__access)

    def read(self, bytesToRead):
        if bytesToRead > 0:
            data =  self.__smbConnection.readFile(self.__tid, self.__fid, self.__currentOffset, bytesToRead)
            self.__currentOffset += len(data)
            return data
        return ''

    def write(self, data):
        self.__smbConnection.writeFile(self.__tid, self.__fid, data)

    def close(self):
        if self.__fid is not None:
            self.__smbConnection.closeFile(self.__tid, self.__fid)
            self.__fid = None

    def delete(self):
        self.__smbConnection.deleteFile(self.__share, self.__fileName)

    def tell(self):
        return self.__currentOffset