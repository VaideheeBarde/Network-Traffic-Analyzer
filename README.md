# Network-Traffic-Analyzer
The objective of this project was to analyze the captured packets and find out which users are downloading software from blacklisted/illegal websites. Source and destination IP addresses are analyzed, and the location of the user is found out. We monitor the user’s packet traversal and find out which users are downloading software/data from these blacklisted sites. We also created a database where we store the geographical locations and all the other details about the packet for future use.

The diagram below exhibits a general view of the network traffic analyzer(Image source - Google)

![NetworkTrafficAnalyzer](https://user-images.githubusercontent.com/22990797/124121209-7700fd80-da29-11eb-973a-2bc29969715b.PNG)

This figure describes the overall working of the application.
The admin continuously monitors different activities performed by the users in the network.
If any user is performing any illegal activity such as performing downloads on illegal or blacklisted sites, then it detects at the admin side.
Then, by using PyGeoIP, the admin correlates the IP address to the physical location of the destination of the packet. This is done by querying the database with a particular IP address. The database returns the record containing the city, region name, postal code, country name, latitude and longitude. 
With the help of this, we can plot the location on Google Earth.
It gives a proof against the user from illegal activity and user cannot deny from it.
The database contains the URL, destination IP, timestamp, latitude, longitude etc. It is stored in an encrypted format to add on to the security of the system. Also, database can be used for future analysis and creating statistics of the illegal activities performed which can help enhancing the security.
Technologies and tools:
Analyzer developed using Python 2.7
MySQL – stores all the info in encrypted format.
GeoLite City database – provides visual location of destination using Google Earth. 
PyGeoLite – correlates IP address to physical location which retrieves the latitude, longitude and region of the user.
Wireshark – used to capture packets (pcap files).
Ettercap – network security tool used in computers for security auditing and network protocol analysis. It is used for intercepting traffic on network segment, conducting active eavesdropping against a number of protocols and capturing passwords.
Google map – displays geographical location of the destination of the packet.
Implementation:
Initially, packets are captured using wireshark and live packet are captured using Ettercap.
Dpkt – a python module used as an analyzing tool for parsing packets. It analyzes each individual packet and analyzes the protocol layer. It provides IP address of the user downloading the application from an illegal or a blacklisted site. 
The geographical location of the packet can be found by using PyGeoIP which queries the GeoLiteCity database.
Also, socket libraries are used to resolve IP addresses to simple strings.
Google maps API gives a geographical display of the destination of the packet that is being analyzed. This display file is obtained in KML format. All the information about the packet i.e. source and destination IP, timestamp, URL, geographical latitude, longitude and location plotted gets stored in the database.
All the information stored in the database is encrypted for security purposes.

