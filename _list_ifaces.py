from scapy.all import IFACES, conf
print("Default:", conf.iface)
print()
for iface in IFACES.values():
    desc = getattr(iface, "description", "")
    name = getattr(iface, "name", "")
    nname = getattr(iface, "network_name", "")
    print(f"name={name!r}  desc={desc!r}  network_name={nname!r}")
