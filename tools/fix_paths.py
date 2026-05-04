import re
f = open('/mnt/d/Projetos-SafeLabs/submodules/IoT/WirelessXPL-Forge/tools/wxf_campaign.py', 'r')
c = f.read()
f.close()
groups = ["wifi_lab", "bluetooth", "pcap", "external", "cellular", "sim"]
for g in groups:
    c = c.replace(f'"{g}/', f'"generic/{g}/')
open('/mnt/d/Projetos-SafeLabs/submodules/IoT/WirelessXPL-Forge/tools/wxf_campaign.py', 'w').write(c)
print('Paths corrigidos')
