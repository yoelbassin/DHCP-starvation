# DHCP Starvation
DHCP starvation attack is an attack that targets DHCP servers whereby forged DHCP requests are crafted by an attacker with the intent of exhausting all available IP addresses that can be allocated by the DHCP server. Under this attack, legitimate network users can be denied service.

to run the attack you should simply run
```
python dhcpStarvation.py
```

If it doesn't run try adding ```sudo``` before the command

However, there are some optional options you could add:

```python dhcpStarvation.py -p``` or ```python dhcpStarvation.py --persistent```
for a persistent attack, the default attack is temporary


```python dhcpStarvation.py -t [TARGET SERVER IP]``` or ```python dhcpStarvation.py --target [TARGET SERVER IP]```
for an attack on a specific server on the network, the default attack is on the first server to reply

```python dhcpStarvation.py -i [NETWORK INTERFACE]``` or ```python dhcpStarvation.py --iface [NETWORK INTERFACE]```
for an attack from a specific network interface (depands on the attackers device), the default attack if from the default interface of your system


 Tested on Kali Linux
