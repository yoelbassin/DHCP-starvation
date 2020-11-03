# DHCP Starvation
DHCP starvation attack is an attack that targets DHCP servers whereby forged DHCP requests are crafted by an attacker with the intent of exhausting all available IP addresses that can be allocated by the DHCP server. Under this attack, legitimate network users can be denied service.

to run the attack you should simply run
```
sudo python dhcpStarvation.py
```

However, there are some optional options you could add:

```sudo python dhcpStarvation.py -p``` or ```sudo python dhcpStarvation.py --persistent```
for a persistent attack, the default attack is temporary


```sudo python dhcpStarvation.py -t [TARGET SERVER IP]``` or ```sudo python dhcpStarvation.py --target [TARGET SERVER IP]```
for an attack on a specific server on the network, the default attack is on the first server to reply

```sudo python dhcpStarvation.py -i [NETWORK INTERFACE]``` or ```sudo python dhcpStarvation.py --iface [NETWORK INTERFACE]```
for an attack from a specific network interface (depands on the attackers device), the default attack if from the default interface of your system


 Tested on Kali Linux
