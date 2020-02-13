import ipaddress, base64

ip = input("Enter IPv6 address: ")
ns = base64.b32encode(ipaddress.IPv6Address(ip).packed)[:26].decode().lower()
print("Config: {{\n\t\"{}\": [\n\t\t\"{}.meshname. AAAA {}\"\n\t]\n}}".format(ns, ns, ip))
