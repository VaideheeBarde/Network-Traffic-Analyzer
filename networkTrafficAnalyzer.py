import sys 
import pygeoip
import dpkt
import socket
import time
import webbrowser

# These dictonaries are used for the key value pairs. Keys being the IP addresses and the values being the lat-long position
abc={}
dest_abc={}

black_listed_ip=['217.168.1.2','192.37.115.0','212.242.33.35','147.137.21.94']

# This dictionary is used for keeping the record of authorized users.

auth_users={"root":"root","soumil":"soumil"}


"""
This function is used for generating information from the IP addresses. It uses the GeoLiteCity data base for doing this .
'gic.record_by_addr()' return a dictonary that has all the parameters of the corresponding IP address. We can print any of them.
"""
def geoip_city(string):
	if string in black_listed_ip:	
		path='/home/soumil/build/geoip/GeoLiteCity.dat'
		gic=pygeoip.GeoIP(path)
		#print gic
		try:	
			a=gic.record_by_addr(string)
			#print a
			pcity=a['city']
			pregion=a['region_code']
			pcountry=a['country_name']
			plong=a['latitude']
			plat=a['longitude']
			print  "\n"	
			print '[*] Target : ' + string + ' Geo Located .'
			print " \n"	
			print '[+] City: '+ str(pcity) + ', Region : '+ str(pregion) + ', Country: ' + str(pcountry)
			print "\n"	
			print '[+] Latitude : ' +  str(plat) + ', Longitude : ' + str(plong)
			print "\n"
		except:
			print " \n ********** IP Unregistered **********"
	else:
		pass



"""
We are using this function to generate latitudes and longitudes an IP address from the GeoLiteCity database. We will be using these Latitudes 
and longitudes fro plotting placemarks on google maps (my maps). This function is used for Source IP addresses.
"""

def kml_geoip_city(string):
	if string in black_listed_ip:
	
		path='/home/soumil/build/geoip/GeoLiteCity.dat'
		gic=pygeoip.GeoIP(path)

		try:	
			a=gic.record_by_addr(string)
			pcity=a['city']
			plong=a['latitude']
			plat=a['longitude']
			abc[str(string)]=str(plat)+","+str(plong)
			# Here we are inputing the IP:lat,long to the source Dictionary defined earlier.
		
		except:
			pass
	else:
		pass


	
"""
We are using this function to generate latitudes and longitudes an IP address from the GeoLiteCity database. We will be using these Latitudes 
and longitudes fro plotting placemarks on google maps (my maps). This function is used for Destination IP addresses.
"""

def kml_dest_geoip_city(string):
	if string in black_listed_ip:
		path='/home/soumil/build/geoip/GeoLiteCity.dat'
		gic=pygeoip.GeoIP(path)

		try:	
			a=gic.record_by_addr(string)
		
			pcity=a['city']
			plong=a['latitude']
			plat=a['longitude']
			dest_abc[str(string)]=str(plat)+","+str(plong)
			# Here we are inputing the IP:lat,long to the destination dictionary defined earlier.
		
		except:

			pass
	else:
		pass



"""
The printcap function is used for printing information related to a particular IP address. This function takes in a pcap. 
It uses the dptk module in python to parse the pcap to find out all the source IP and destination IP of all the packets.
It now prints all the information on the screen in text format.
"""
	
	
def printpcap(pcap):
	for (ts,buf) in pcap:
		try:
			eth=dpkt.ethernet.Ethernet(buf)
			ip=eth.data
			src=socket.inet_ntoa(ip.src)
			dst=socket.inet_ntoa(ip.dst)
			if src in black_listed_ip:
			
				print "-------------------------------------------------------------------------------------------------"
				print '[+] Source IP: '+str(src)+ '------->  Destination IP: '+ str(dst)
				print "Source IP Information:"			
				print geoip_city(str(src))
			elif dst in black_listed_ip:
			
				print "=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-"
				print "Destination IP Information:"
				print geoip_city(str(dst))
				print "--------------------------------------------------------------------------------------------------"
			else:
				pass

		except:
			pass

"""
The view_google function is some what similar to the printpcap function that is written above.
Even this function takes in a pcap, parses it using 'dpkt' and then sends the source and dest ip addresses
to the fnction that generates kml format for the data so that it can be used to represet on a graph.
"""
def view_google(pcap):	
	
	for (ts,buf) in pcap:
		try:
			eth=dpkt.ethernet.Ethernet(buf)
			ip=eth.data
			src=socket.inet_ntoa(ip.src)
			dst=socket.inet_ntoa(ip.dst)
			kml_geoip_city(str(src))
			kml_dest_geoip_city(str(dst))
			
		except:
			pass

"""
The print_placemarks_in_kml(abc) funtion is used for generating the kml format of the data for the representation of the 
google maps. It takes in a dictionary  that contains key-value pairs (IP:lat,long). And inturn generate the kml format 
of the data. This function is used for generating kml for Source IP addresses.
"""

def print_placemarks_in_kml(abc):
	for i in abc.keys():
		print """
  <Placemark>
    <name> SOURCE IP Address: %s</name>
    <styleUrl>#exampleStyleDocument</styleUrl>
    <Point>
      <coordinates>%s</coordinates>
    </Point>
  </Placemark>
"""%(i,abc[i])



"""
The print_dest_placemarks_in_kml(dest_abc) funtion is used for generating the kml format of the data for  the representation of the 
google maps. It takes in a dictionary  that contains key-value pairs (IP:lat,long). And inturn generate the kml format 
of the data. This function is used for generating kml for destication IP addresses.
"""

def print_dest_placemarks_in_kml(dest_abc):
	for i in dest_abc.keys():
		print """
  <Placemark>
    <name> DESTINATION IP Address: %s</name>
    <styleUrl>#exampleStyleDocument</styleUrl>
    <Point>
      <coordinates>%s</coordinates>
    </Point>
  </Placemark>
"""%(i,dest_abc[i])
	



"""
Now the main function starts : 
"""

"""
The first try-catch block is used to validate if the user is authorized to use this tool. If the username entered by the user is present in 
our record (i.e. the dictionary"auth_users"), he/she gets to use the tool. Else One cannot access the tool. This can be considered as one of 
the security feature of our tool.
"""

if len(sys.argv)<2:
	print "\n -------------------- Please enter the required arguments------------------------- "
	print "\n Correct syntax is : <FileName>.py username password cli/kml\n"
	print "\ncli- stands for Command Line Output"
	print "\nkml- stands fro a KML output which is required for visualization using a Google Map"

else:

	try:
		if str(sys.argv[1]) in auth_users:

			"""
			The second try-catch block is used to validate the password entered by the user to the corresponding entered username. Once the username is 
			validated, we must validate the password as well. This is used fro securit hardening of the tool.
			"""

			try:
				if str(sys.argv[2])==auth_users[str(sys.argv[1])]:

					"""
					The user must specify what type of output does he/she desire. If he/she desires an output on the command line or a textual output
					he should use "cli" option.
					If he/she desires to use maps for visualizaing the contents of the analysis. There is a need for a KML file that must 
					be uploaded to the google maps webiste that opens an the end.
					For Visualizing it output on the maps. He/She must redirect the output of the program using pipes to a ".kml" file. 
					This .kml file is then uploded on the mymaps website.
					"""
					try:
	
						if str(sys.argv[3])=="cli":
							f=open('/home/soumil/Downloads/fuzz-2006-06-26-2594.pcap')
							pcap=dpkt.pcap.Reader(f)
							printpcap(pcap)
							f.close()
							sys.exit(1)
						elif str(sys.argv[3])=="kml":
		
							print """
						<?xml version="1.0" encoding="UTF-8"?>
						<kml xmlns="http://www.opengis.net/kml/2.2">
						<Document>
						  <name>sourceip.kml</name>
						  <open>1</open>
						  <Style id="exampleStyleDocument">
						    <LabelStyle>
						      <color>ff0000cc</color>
						    </LabelStyle>
						  </Style>\n"""	
							f=open('/home/soumil/Downloads/fuzz-2006-06-26-2594.pcap')
							pcap=dpkt.pcap.Reader(f)
							view_google(pcap)
							f.close()
							print_dest_placemarks_in_kml(dest_abc)
							print_placemarks_in_kml(abc)
							#print abc
							print """\n
						</Document>
						</kml>
						"""
							new=1
							url="https://www.google.com/maps/d/splash?app=mp"
							webbrowser.open(url,new=new)
						


						else:
							raise exception
						

					except:
						print "\nYou Entered a worng option. Or may be your Syntax is wrong"
						print "\n Correct syntax is : <FileName>.py username password cli/kml\n"
						print "\ncli- stands for Command Line Output"
						print "\nkml- stands fro a KML output which is required for visualization using a Google Map"
				else:
					raise exception
				

			except:
				print "\n The PASSWORD you entered is NOT CORRECT !!!!!! "
				print "\n Correct syntax is : <FileName>.py username password cli/kml\n"
				print "\ncli- stands for Command Line Output"
				print "\nkml- stands fro a KML output which is required for visualization using a Google Map"

		else:

			raise exception


	except:

		print "\n Sorry %s. You are NOT AUTHORIZED to use this tool!!!!!!!!!!!"%str(sys.argv[1])
		print "\n Correct syntax is : <FileName>.py username password cli/kml\n"
		print "\ncli- stands for Command Line Output"
		print "\nkml- stands fro a KML output which is required for visualization using a Google Map"
