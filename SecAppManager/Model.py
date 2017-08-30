""" Model for Security Appliance Wrappers """
import re
class SecApp:
    """ Class for Security Appliance Wrappers """
    def __init__(self, group, hw_addr, token, misc=''):
        """
        Create a Model for Security Appliance Wrapper
        :param group:
        :param hw_addr:
        :param token:
        :param misc:
        """
        # { "type": "REGISTER", "group": "saGroup", "hw_addr": "mac-address", "token":
        # "secureToken", "misc": "misc info" }
        self.group = group
        self.token = token
        self.hw_addr = hw_addr
        self.instance_id = str(self.group)+"-"+str(id(self))
        self.misc = misc
        if not (len(hw_addr) == 17 and
                re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", hw_addr)):
            raise ValueError("HW_ADDR is invalid.")

    def equals(self, obj):
        """
        Checks if this instance is equal to obj.
        :param obj:
        :return:
        """
        if isinstance(obj, SecApp):
            if self.group == obj.group:
                if self.hw_addr == obj.hw_addr:
                    return True
        return False
