# external Libraries

# standard Libraries
import re, sys

class SecApp():

    def __init__(self, group, hw_addr, token, misc):
        # { "type": "REGISTER", "group": "saGroup", "hw_addr": "mac-address", "token": "secureToken", "misc": "misc info" }
        self.group = group
        self.token = token
        self.hw_addr = hw_addr
        self.instanceID = str(self.group)+"-"+str(id(self))
        self.misc = misc
        if(not (len(hw_addr) == 17 and re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", hw_addr))):
                raise ValueError("HW_ADDR is invalid.")

    def equals(self, obj):
        if(isinstance(obj, SecApp)):
            if(self.group == obj.group):
                if(self.hw_addr == obj.hw_addr):
                    return True
        return False