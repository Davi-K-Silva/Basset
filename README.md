# Basset

Sniffer de rede em C

## Como utilizar:

Se necessário compile o programa: 
```
gcc Basset.c -o basset
```
Após compilado execute o programa com:

```
sudo ./basset [Netkork interface] [N Packages]
```

Um possivel exemplo com wifi, ele ira utilizaar o wifi e recebera 10 pacotes:

```
sudo ./basset wlp4s0 10
```

Saída:

                __
    (\,--------'()'--o
    (_    ___  ()/~´    SNIFF... SNIFF...
    (_)_)  (_)_)
    PROT | Source         | Destination      | Size   | Info
    ICMP6  2804:d51:435...   2804:d51:435...   86                       
    ARP    192.168.1.254     192.168.1.28      60      Request
    ICMP6  2804:d51:435...   2804:d51:435...   78                     
    ARP    192.168.1.28      192.168.1.254     42      Reply
    UDP    192.168.1.3       255.255.255.255   230     49154->6667      
    ARP    192.168.1.3       192.168.1.3       42      Request
    ICMP6  fe80::1           fe80::3cc4:b...   86                     
    ICMP6  fe80::3cc4:b...   fe80::1           78                       
    TCP    52.89.217.163     192.168.1.28      97      HTTPS->42868     
    TCP    192.168.1.28      52.89.217.163     101     42868->HTTPS     

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    Mean: 90.0 B | Max: 230 B | Min: 42 B 
    Ipv4:  3   | 30.0% 
    Ipv6:  4   | 40.0% 
    ARP:   3   | 30.0% | Req: 2  | Rep: 1  
    ICMP:  0   | 0.0% | Req: 0  | Rep: 0  
    ICMP6: 4   | 40.0% | Req: 0  | Rep: 0  
    UDP:   1   | 10.0% 
    TCP:   2   | 20.0% 
    DNS:   0   | 0.0% 
    DHCP:  0   | 0.0% 
    HTTP:  0   | 0.0% 
    HTTPS: 1   | 10.0% 
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

