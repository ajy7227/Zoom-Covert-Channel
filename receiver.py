import pyshark
import sys

# Determine Zoom IP and length of ones
def init1(pcap):
	packet_occurance = {}
	# For each entry in pcap
	for packet in pcap:
		# Determine if IP packet
		try:
			source_IP = packet.ip.src
			packet_length = int(packet.length)

			# If ssl and length over 900 (then its a potential handraise)
			if packet.ssl and packet_length > 900:
				# First IP with 7 occurances is assumed to be zoom
				if (source_IP,packet_length) not in packet_occurance:
					packet_occurance[(source_IP,packet_length)] = 1
				else:
					packet_occurance[(source_IP,packet_length)] += 1
		# If not packet, pass
		except AttributeError as e:
			pass

		for elmt in packet_occurance:

			if packet_occurance[elmt] == 7:
				return elmt


# Get zero length
def init2(pcap, zoom_IP):
	packet_occurance = {}
	# For each entry in pcap
	for packet in pcap:
		# Determine if IP packet
		try:
			source_IP = packet.ip.src
			packet_length = int(packet.length)

			# If ssl and length over 900 (then its a potential handraise)
			if packet.ssl and 100 < packet_length < 200 and source_IP == zoom_IP:
				if packet_length not in packet_occurance:
					packet_occurance[packet_length] = 1
				else:
					packet_occurance[packet_length] += 1
		# If not packet, pass
		except AttributeError as e:
			pass

		for elmt in packet_occurance:
			if packet_occurance[elmt] == 7:
				return elmt



def decode(pcap, zoom_IP, one_length, zero_length):
	init = False
	delim_count = 0
	message = ""
	binary = ""
	for packet in pcap:
		try:

			source_IP = packet.ip.src
			packet_length = int(packet.length)

			if source_IP == zoom_IP:
				if packet_length == one_length:
					binary+="1"
				elif packet_length == zero_length:
					binary+="0"

			# Manipluate delimeter count
			if packet_length==one_length:
				delim_count+=1
			elif packet_length==zero_length:
				delim_count=0

			# if delimeter count reaches 7 then message is complete
			if delim_count==7 and init==False:
				init = True
				delim_count = 0
			if init and delim_count==7:
				break


		# If not packet, pass
		except AttributeError as e:
			pass

	binary = binary[14:]


	for i in range(0,len(binary),8):
		bin = binary[i:i + 8]
		# Disregard bits that arent full octet
		if len(bin) == 8:
			message += chr(int(bin,2))



	return message

# Main
def main():

	pcap = pyshark.FileCapture(sys.argv[1], display_filter='!tcp.analysis.retransmission && ssl')

	zoom_IP, one_length = init1(pcap)

	zero_length = init2(pcap, zoom_IP)

	message = decode(pcap, zoom_IP, one_length, zero_length)


	print(message)


main()
