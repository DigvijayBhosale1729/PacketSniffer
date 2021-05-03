# PacketSniffer
PacketSniffer is a python tool that can sniff packets on any interface and extract sensitive information like Usernames and Passwords along with the server IP, TCP Seq, cookies, referers etc. It has been written for Python3 and uses Scapy.

## Prerequisites

Install _scapy_ using

```
sudo pip install scapy
```

## Usage

Run the script (as root) by
```
python3 PacketSniffer.py 
```

![image](https://user-images.githubusercontent.com/70275323/116866005-4b7bb580-ac28-11eb-8a5a-00832d650baf.png)

Entering ```1``` will show the results of ```ifconfig``` that can be used to select the interface.

Entering ```2``` will prompt you into entering the info and verbosity and will start the actual sniffing

![image](https://user-images.githubusercontent.com/70275323/116866105-76fea000-ac28-11eb-8028-0e4c7fd151db.png)

Recommended Verbosity levels are ```3``` and ```4``` they display most of the import information. 

However, if you need even more information, feel free to examine the entire packet using verbosity ```5```

As an example, I've used [Vulnhub Login](testphp.vulnweb.com/login.php) to demonstrate the use of this script

![image](https://user-images.githubusercontent.com/70275323/116866516-263b7700-ac29-11eb-9b19-f80b7c82ae44.png)

To change interfaces, or exit out of the script, press ```Ctrl + C```

This will bring you back to the initial prompt where you can choose to open ifconfig, sniff, or exit.

![image](https://user-images.githubusercontent.com/70275323/116867471-e7a6bc00-ac2a-11eb-9e7a-6d99f55dd53e.png)

#### Final Words

Many thanks to Zaid Sabih and Udemy.com who taught me to write this program. I've learnt a lot while i was writing this and one of the things i've learnt to do is reading the docs. The scapy docs are huge and the module itself has a large amount of things that can be done. Selecting the correct class and using the correct keywords in case of Scapy wasnt like other modules i've used so far where it was as simple as typing a letter and letting autocomplete do the rest of the job. 

Reading the docs, understanding how modules work, and understanding how packets are crafted is something i wouldn't have learnt out of a textbook, and getting hands on experience using this knowledge was invaluable.

Thanks again
