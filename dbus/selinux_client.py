import dbus
import dbus.service
from sepolicy.sedbus import SELinuxDBus


def convert_customization(buf):
    cust_dict = {}
    cust_dict["fcontext-equiv"] = {}
    for i in buf.split("\n"):
        rec = i.split()
        if len(rec) == 0:
            continue
        if rec[1] == "-D":
            continue
        if rec[0] not in cust_dict:
            cust_dict[rec[0]] = {}
        if rec[0] == "boolean":
            cust_dict["boolean"][rec[-1]] = {"active": rec[2] == "-1"}
        if rec[0] == "login":
            cust_dict["login"][rec[-1]] = {"seuser": rec[3], "range": rec[5]}
        if rec[0] == "interface":
            cust_dict["login"][rec[-1]] = {"type": rec[3]}
        if rec[0] == "user":
            cust_dict["user"][rec[-1]] = {"level": rec[3], "range": rec[5], "role": rec[7]}
        if rec[0] == "port":
            cust_dict["port"][(rec[-1], rec[-2])] = {"type": rec[3]}
        if rec[0] == "node":
            cust_dict["node"][rec[-1]] = {"mask": rec[3], "protocol": rec[5], "type": rec[7]}
        if rec[0] == "fcontext":
            if rec[2] == "-e":
                cust_dict["fcontext-equiv"][(rec[-1])] = {"equiv": rec[3]}
            else:
                cust_dict["fcontext"][(rec[-1], rec[3])] = {"type": rec[5]}
        if rec[0] == "module":
            cust_dict["module"][rec[-1]] = {"enabled": rec[2] != "-d"}

    return cust_dict
if __name__ == "__main__":
    try:
        dbus_proxy = SELinuxDBus()
        resp = dbus_proxy.customized()
        print(convert_customization(resp))
    except dbus.DBusException as e:
        print(e)
