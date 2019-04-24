
## Set 1:
### Clyde: 
print("Set 1:")
from scapy.all import *
packets_clyde1 = rdpcap("/home/mawla/Data_522/clyde_1547.cap")
len(packets_clyde1)
print("----------------------------------")
print("Clyde Building Data:")
print("----------------------------------")
print("Total "+ str(len(packets_clyde1)) + " packets were read")
print("----------------------------------")



Data_clyde1 = 0
Control_clyde1 = 0
Management_clyde1 = 0 

Beacon_clyde1 = 0
AssoReq_clyde1 = 0	
AssoResp_clyde1 = 0
Auth_clyde1 = 0
Deauth_clyde1 = 0
Disas_clyde1 = 0
ProbeReq_clyde1 = 0
ProbeResp_clyde1 = 0
ReassoReq_clyde1 = 0
ReassoResp_clyde1 = 0
ATIM_clyde1 = 0
Others_mgmt_clyde1 = 0


PS_clyde1 = 0
RTS_clyde1 = 0
CTS_clyde1 = 0
Acknowledgement_clyde1 = 0
CFEnd_clyde1 = 0
CFEnd_Ack_clyde1 = 0
Others_ctl_clyde1 = 0

data_clyde1 = 0
data_cf_ack_clyde1 = 0
data_cf_poll_clyde1 = 0
data_cf_ack_cf_poll_clyde1 = 0
null_data_clyde1 = 0
cf_ack_clyde1 = 0
cf_poll_clyde1 = 0
cf_ack_cf_poll_clyde1 = 0
Others_data_clyde1 = 0


for i in range(0, len(packets_clyde1)):
	if packets_clyde1[i][Dot11].type == 0:
		Management_clyde1 = Management_clyde1 + 1
		if packets_clyde1[i].haslayer(Dot11Beacon) == 1:
			Beacon_clyde1 = Beacon_clyde1 + 1
		elif packets_clyde1[i].haslayer(Dot11AssoReq) == 1:
			AssoReq_clyde1 = AssoReq_clyde1 + 1
		elif packets_clyde1[i].haslayer(Dot11AssoResp) == 1:
			AssoResp_clyde1 = AssoResp_clyde1 + 1
		elif packets_clyde1[i].haslayer(Dot11Auth) == 1:
			Auth_clyde1 = Auth_clyde1 + 1
		elif packets_clyde1[i].haslayer(Dot11Deauth) == 1:
			Deauth_clyde1 = Deauth_clyde1 + 1
		elif packets_clyde1[i].haslayer(Dot11Disas) == 1:
			Disas_clyde1 = Disas_clyde1 + 1
		elif packets_clyde1[i].haslayer(Dot11ProbeReq) == 1:
			ProbeReq_clyde1 = ProbeReq_clyde1 + 1
		elif packets_clyde1[i].haslayer(Dot11ProbeResp) == 1:
			ProbeResp_clyde1 = ProbeResp_clyde1 + 1
		elif packets_clyde1[i].haslayer(Dot11ReassoReq) == 1:
			ReassoReq_clyde1 = ReassoReq_clyde1 + 1
		elif packets_clyde1[i].haslayer(Dot11ReassoResp) == 1:
			ReassoResp_clyde1= ReassoResp_clyde1 + 1
		elif packets_clyde1[i].haslayer(Dot11ATIM) == 1:
			ATIM_clyde1 = ATIM_clyde1 + 1
		else:
			Others_mgmt_clyde1 = Others_mgmt_clyde1 + 1

	elif packets_clyde1[i][Dot11].type == 1:
		Control_clyde1 = Control_clyde1 + 1
		if packets_clyde1[i][Dot11].subtype == 10:
			PS_clyde1 = PS_clyde1 + 1
		elif packets_clyde1[i][Dot11].subtype == 11:
			RTS_clyde1 = RTS_clyde1 + 1
		elif packets_clyde1[i][Dot11].subtype == 12:
			CTS_clyde1 = CTS_clyde1 + 1
		elif packets_clyde1[i][Dot11].subtype == 13:
			Acknowledgement_clyde1 = Acknowledgement_clyde1 + 1
		elif packets_clyde1[i][Dot11].subtype == 14:
			CFEnd_clyde1 = CFEnd_clyde1 + 1
		elif packets_clyde1[i][Dot11].subtype == 15:
			CFEnd_Ack_clyde1 = CFEnd_Ack_clyde1 + 1
		else:
			Others_ctl_clyde1 = Others_ctl_clyde1 + 1
			
	elif packets_clyde1[i][Dot11].type == 2:
		Data_clyde1 = Data_clyde1 + 1
		if packets_clyde1[i][Dot11].subtype == 0:
			data_clyde1 = data_clyde1 + 1
		elif packets_clyde1[i][Dot11].subtype == 1:
			data_cf_ack_clyde1 = data_cf_ack_clyde1 + 1
		elif packets_clyde1[i][Dot11].subtype == 2:
			data_cf_poll_clyde1 = data_cf_poll_clyde1 + 1
		elif packets_clyde1[i][Dot11].subtype == 3:
			data_cf_ack_cf_poll_clyde1 = data_cf_ack_cf_poll_clyde1 + 1
		elif packets_clyde1[i][Dot11].subtype == 4:
			null_data_clyde1 = null_data_clyde1 + 1
		elif packets_clyde1[i][Dot11].subtype == 5:
			cf_ack_clyde1 = cf_ack_clyde1 + 1
		elif packets_clyde1[i][Dot11].subtype == 6:
			cf_poll_clyde1 = cf_poll_clyde1 + 1
		elif packets_clyde1[i][Dot11].subtype == 7:
			cf_ack_cf_poll_clyde1 = cf_ack_cf_poll_clyde1 + 1
		else: 
			Others_data_clyde1 = Others_data_clyde1 + 1

			
print("Management Frames: " + str(Management_clyde1))
print("Control Frames: " + str(Control_clyde1))
print("Data Frames: " + str(Data_clyde1)) 
print("----------------------------------")


print("Beacon Frames: " + str(Beacon_clyde1))
print("Association Request Frames: " +str(AssoReq_clyde1))
print("Association Response Frames: " +str(AssoResp_clyde1))
print("Authentication Frames: "+str(Auth_clyde1))
print("Deauthentication Frames: "+str(Deauth_clyde1))
print("Dissociation Frames: "+str(Disas_clyde1))
print("Probe Request Frames: " +str(ProbeReq_clyde1))
print("Probe Response Frames: " +str(ProbeResp_clyde1))
print("Reassociation Request Frames: "+str(ReassoReq_clyde1))
print("Reassociation Response Frames: "+str(ReassoResp_clyde1))
print("Announcement traffic indication message: "+str(ATIM_clyde1))
print("Other Management Frames: "+str(Others_mgmt_clyde1))
print("----------------------------------")


print("Power Save (PS) Poll Frames: " + str(PS_clyde1))
print("Request to Send (RTS) Frames: " + str(RTS_clyde1))
print("Clear to Send (CTS) Frames: " + str(CTS_clyde1))
print("Acknowledgement Frames: " + str(Acknowledgement_clyde1))
print("Contention Free (CF)- End Frames: " + str(CFEnd_clyde1))
print("Contention Free (CF)- End + Ack Frames: " + str(CFEnd_Ack_clyde1))
print("Other Control Frames: "+str(Others_ctl_clyde1))
print("----------------------------------")

print("Data frames: "+str(data_clyde1))
print("Data + CF-Acknowledgement frames: "+str(data_cf_ack_clyde1))
print("Data + CF-Poll frames: "+str(data_cf_poll_clyde1))
print("Data + CF-Acknowledgement + CF-Poll frames: "+str(data_cf_ack_cf_poll_clyde1))
print("Null Data frames: "+str(null_data_clyde1))
print("CF-Acknowledgement (no data) frames: "+str(cf_ack_clyde1))
print("CF-Poll (no data) frames: "+str(cf_poll_clyde1))
print("CF-Acknowledgement + CF-Poll (no data) frames: "+str(cf_ack_cf_poll_clyde1))
print("Other Data Frames: "+str(Others_data_clyde1))
print("----------------------------------")



import matplotlib.pyplot as plt
main_frame_values_clyde1 = [Data_clyde1, Control_clyde1, Management_clyde1]
main_frame_type_clyde1 = ['Data Frame','Control Frame','Management Frame']
cols = ['m', 'r','g']
plt.pie(main_frame_values_clyde1,labels=main_frame_type_clyde1,colors=cols,autopct='%1.1f%%')
plt.title('Frame Types in Clyde Building: Data Set 1')
plt.show()

mgmt_frame_values_clyde1 = [Beacon_clyde1, Auth_clyde1, ProbeReq_clyde1, ProbeResp_clyde1, Others_mgmt_clyde1]
mgmt_frame_type_clyde1 = ['Beacon Frame','Authentication Frames','Probe Request Frames','Probe Response Frames','Other']
cols = ['b', 'g','r','c','m']
plt.pie(mgmt_frame_values_clyde1,labels=mgmt_frame_type_clyde1,colors=cols,autopct='%1.1f%%')
plt.title('Management Frame Types in Clyde Building: Data Set 1')
plt.show()

ctl_frame_values_clyde1 = [CTS_clyde1, Acknowledgement_clyde1, Others_ctl_clyde1]
ctl_frame_type_clyde1 = ['Clear to Send (CTS) Frames','Acknowledgement Frames','Other']
cols = ['b', 'g','r']
plt.pie(ctl_frame_values_clyde1,labels=ctl_frame_type_clyde1,colors=cols,autopct='%1.1f%%')
plt.title('Control Frame Types in Clyde Building: Data Set 1')
plt.show()


data_frame_values_clyde1 = [data_clyde1, null_data_clyde1, Others_data_clyde1]
data_frame_type_clyde1 = ['Data Frames','Null Data Frames','Other']
cols = ['b', 'g','r']
plt.pie(data_frame_values_clyde1,labels=data_frame_type_clyde1,colors=cols,autopct='%1.1f%%')
plt.title('Data Frame Types in Clyde Building: Data Set 1')
plt.show()


### Wilk:

from scapy.all import *
packets_wilk1 = rdpcap("/home/mawla/Data_522/wilk_1555.cap")
len(packets_wilk1)
print("----------------------------------")
print("Wilk Student Center Data:")
print("----------------------------------")
print("Total "+ str(len(packets_wilk1)) + " packets were read")
print("----------------------------------")



Data_wilk1 = 0
Control_wilk1 = 0
Management_wilk1 = 0 

Beacon_wilk1 = 0
AssoReq_wilk1 = 0	
AssoResp_wilk1 = 0
Auth_wilk1 = 0
Deauth_wilk1 = 0
Disas_wilk1 = 0
ProbeReq_wilk1 = 0
ProbeResp_wilk1 = 0
ReassoReq_wilk1 = 0
ReassoResp_wilk1 = 0
ATIM_wilk1 = 0
Others_mgmt_wilk1 = 0


PS_wilk1 = 0
RTS_wilk1 = 0
CTS_wilk1 = 0
Acknowledgement_wilk1 = 0
CFEnd_wilk1 = 0
CFEnd_Ack_wilk1 = 0
Others_ctl_wilk1 = 0

data_wilk1 = 0
data_cf_ack_wilk1 = 0
data_cf_poll_wilk1 = 0
data_cf_ack_cf_poll_wilk1 = 0
null_data_wilk1 = 0
cf_ack_wilk1 = 0
cf_poll_wilk1 = 0
cf_ack_cf_poll_wilk1 = 0
Others_data_wilk1 = 0


for i in range(0, len(packets_wilk1)):
	if packets_wilk1[i][Dot11].type == 0:
		Management_wilk1 = Management_wilk1 + 1
		if packets_wilk1[i].haslayer(Dot11Beacon) == 1:
			Beacon_wilk1 = Beacon_wilk1 + 1
		elif packets_wilk1[i].haslayer(Dot11AssoReq) == 1:
			AssoReq_wilk1 = AssoReq_wilk1 + 1
		elif packets_wilk1[i].haslayer(Dot11AssoResp) == 1:
			AssoResp_wilk1 = AssoResp_wilk1 + 1
		elif packets_wilk1[i].haslayer(Dot11Auth) == 1:
			Auth_wilk1 = Auth_wilk1 + 1
		elif packets_wilk1[i].haslayer(Dot11Deauth) == 1:
			Deauth_wilk1 = Deauth_wilk1 + 1
		elif packets_wilk1[i].haslayer(Dot11Disas) == 1:
			Disas_wilk1 = Disas_wilk1 + 1
		elif packets_wilk1[i].haslayer(Dot11ProbeReq) == 1:
			ProbeReq_wilk1 = ProbeReq_wilk1 + 1
		elif packets_wilk1[i].haslayer(Dot11ProbeResp) == 1:
			ProbeResp_wilk1 = ProbeResp_wilk1 + 1
		elif packets_wilk1[i].haslayer(Dot11ReassoReq) == 1:
			ReassoReq_wilk1 = ReassoReq_wilk1 + 1
		elif packets_wilk1[i].haslayer(Dot11ReassoResp) == 1:
			ReassoResp_wilk1= ReassoResp_wilk1 + 1
		elif packets_wilk1[i].haslayer(Dot11ATIM) == 1:
			ATIM_wilk1 = ATIM_wilk1 + 1
		else:
			Others_mgmt_wilk1 = Others_mgmt_wilk1 + 1

	elif packets_wilk1[i][Dot11].type == 1:
		Control_wilk1 = Control_wilk1 + 1
		if packets_wilk1[i][Dot11].subtype == 10:
			PS_wilk1 = PS_wilk1 + 1
		elif packets_wilk1[i][Dot11].subtype == 11:
			RTS_wilk1 = RTS_wilk1 + 1
		elif packets_wilk1[i][Dot11].subtype == 12:
			CTS_wilk1 = CTS_wilk1 + 1
		elif packets_wilk1[i][Dot11].subtype == 13:
			Acknowledgement_wilk1 = Acknowledgement_wilk1 + 1
		elif packets_wilk1[i][Dot11].subtype == 14:
			CFEnd_wilk1 = CFEnd_wilk1 + 1
		elif packets_wilk1[i][Dot11].subtype == 15:
			CFEnd_Ack_wilk1 = CFEnd_Ack_wilk1 + 1
		else:
			Others_ctl_wilk1 = Others_ctl_wilk1 + 1
			
	elif packets_wilk1[i][Dot11].type == 2:
		Data_wilk1 = Data_wilk1 + 1
		if packets_wilk1[i][Dot11].subtype == 0:
			data_wilk1 = data_wilk1 + 1
		elif packets_wilk1[i][Dot11].subtype == 1:
			data_cf_ack_wilk1 = data_cf_ack_wilk1 + 1
		elif packets_wilk1[i][Dot11].subtype == 2:
			data_cf_poll_wilk1 = data_cf_poll_wilk1 + 1
		elif packets_wilk1[i][Dot11].subtype == 3:
			data_cf_ack_cf_poll_wilk1 = data_cf_ack_cf_poll_wilk1 + 1
		elif packets_wilk1[i][Dot11].subtype == 4:
			null_data_wilk1 = null_data_wilk1 + 1
		elif packets_wilk1[i][Dot11].subtype == 5:
			cf_ack_wilk1 = cf_ack_wilk1 + 1
		elif packets_wilk1[i][Dot11].subtype == 6:
			cf_poll_wilk1 = cf_poll_wilk1 + 1
		elif packets_wilk1[i][Dot11].subtype == 7:
			cf_ack_cf_poll_wilk1 = cf_ack_cf_poll_wilk1 + 1
		else: 
			Others_data_wilk1 = Others_data_wilk1 + 1

			
print("Management Frames: " + str(Management_wilk1))
print("Control Frames: " + str(Control_wilk1))
print("Data Frames: " + str(Data_wilk1)) 
print("----------------------------------")


print("Beacon Frames: " + str(Beacon_wilk1))
print("Association Request Frames: " +str(AssoReq_wilk1))
print("Association Response Frames: " +str(AssoResp_wilk1))
print("Authentication Frames: "+str(Auth_wilk1))
print("Deauthentication Frames: "+str(Deauth_wilk1))
print("Dissociation Frames: "+str(Disas_wilk1))
print("Probe Request Frames: " +str(ProbeReq_wilk1))
print("Probe Response Frames: " +str(ProbeResp_wilk1))
print("Reassociation Request Frames: "+str(ReassoReq_wilk1))
print("Reassociation Response Frames: "+str(ReassoResp_wilk1))
print("Announcement traffic indication message: "+str(ATIM_wilk1))
print("Other Management Frames: "+str(Others_mgmt_wilk1))
print("----------------------------------")


print("Power Save (PS) Poll Frames: " + str(PS_wilk1))
print("Request to Send (RTS) Frames: " + str(RTS_wilk1))
print("Clear to Send (CTS) Frames: " + str(CTS_wilk1))
print("Acknowledgement Frames: " + str(Acknowledgement_wilk1))
print("Contention Free (CF)- End Frames: " + str(CFEnd_wilk1))
print("Contention Free (CF)- End + Ack Frames: " + str(CFEnd_Ack_wilk1))
print("Other Control Frames: "+str(Others_ctl_wilk1))
print("----------------------------------")

print("Data frames: "+str(data_wilk1))
print("Data + CF-Acknowledgement frames: "+str(data_cf_ack_wilk1))
print("Data + CF-Poll frames: "+str(data_cf_poll_wilk1))
print("Data + CF-Acknowledgement + CF-Poll frames: "+str(data_cf_ack_cf_poll_wilk1))
print("Null Data frames: "+str(null_data_wilk1))
print("CF-Acknowledgement (no data) frames: "+str(cf_ack_wilk1))
print("CF-Poll (no data) frames: "+str(cf_poll_wilk1))
print("CF-Acknowledgement + CF-Poll (no data) frames: "+str(cf_ack_cf_poll_wilk1))
print("Other Data Frames: "+str(Others_data_wilk1))

main_frame_values_wilk1 = [Data_wilk1, Control_wilk1, Management_wilk1]
main_frame_type_wilk1 = ['Data Frame','Control Frame','Management Frame']
cols = ['m', 'r','g']
plt.pie(main_frame_values_wilk1,labels=main_frame_type_wilk1,colors=cols,autopct='%1.1f%%')
plt.title('Frame Types in Wilk Student Center: Data Set 1')
plt.show()


mgmt_frame_values_wilk1 = [Beacon_wilk1, Auth_wilk1, ProbeReq_wilk1, ProbeResp_wilk1, Others_mgmt_wilk1]
mgmt_frame_type_wilk1 = ['Beacon Frame','Authentication Frames','Probe Request Frames','Probe Response Frames','Other']
cols = ['b', 'g','r','c','m']
plt.pie(mgmt_frame_values_wilk1,labels=mgmt_frame_type_wilk1,colors=cols,autopct='%1.1f%%')
plt.title('Management Frame Types in Wilk Student Center Building: Data Set 1')
plt.show()

ctl_frame_values_wilk1 = [CTS_wilk1, Acknowledgement_wilk1, Others_ctl_wilk1]
ctl_frame_type_wilk1 = ['Clear to Send (CTS) Frames','Acknowledgement Frames','Other']
cols = ['b', 'g','r']
plt.pie(ctl_frame_values_wilk1,labels=ctl_frame_type_wilk1,colors=cols,autopct='%1.1f%%')
plt.title('Control Frame Types in Wilk Student Center: Data Set 1')
plt.show()

data_frame_values_wilk1 = [data_wilk1, null_data_wilk1, Others_data_wilk1]
data_frame_type_wilk1 = ['Data Frames','Null Data Frames','Other']
cols = ['b', 'g','r']
plt.pie(data_frame_values_wilk1,labels=data_frame_type_wilk1,colors=cols,autopct='%1.1f%%')
plt.title('Data Frame Types in Wilk Student Center: Data Set 1')
plt.show()


### library: 

from scapy.all import *
packets_library1 = rdpcap("/home/mawla/Data_522/library_1537.cap")
len(packets_library1)
print("----------------------------------")
print("Library Data:")
print("----------------------------------")
print("Total "+ str(len(packets_library1)) + " packets were read")
print("----------------------------------")



Data_library1 = 0
Control_library1 = 0
Management_library1 = 0 

Beacon_library1 = 0
AssoReq_library1 = 0	
AssoResp_library1 = 0
Auth_library1 = 0
Deauth_library1 = 0
Disas_library1 = 0
ProbeReq_library1 = 0
ProbeResp_library1 = 0
ReassoReq_library1 = 0
ReassoResp_library1 = 0
ATIM_library1 = 0
Others_mgmt_library1 = 0


PS_library1 = 0
RTS_library1 = 0
CTS_library1 = 0
Acknowledgement_library1 = 0
CFEnd_library1 = 0
CFEnd_Ack_library1 = 0
Others_ctl_library1 = 0

data_library1 = 0
data_cf_ack_library1 = 0
data_cf_poll_library1 = 0
data_cf_ack_cf_poll_library1 = 0
null_data_library1 = 0
cf_ack_library1 = 0
cf_poll_library1 = 0
cf_ack_cf_poll_library1 = 0
Others_data_library1 = 0


for i in range(0, len(packets_library1)):
	if packets_library1[i][Dot11].type == 0:
		Management_library1 = Management_library1 + 1
		if packets_library1[i].haslayer(Dot11Beacon) == 1:
			Beacon_library1 = Beacon_library1 + 1
		elif packets_library1[i].haslayer(Dot11AssoReq) == 1:
			AssoReq_library1 = AssoReq_library1 + 1
		elif packets_library1[i].haslayer(Dot11AssoResp) == 1:
			AssoResp_library1 = AssoResp_library1 + 1
		elif packets_library1[i].haslayer(Dot11Auth) == 1:
			Auth_library1 = Auth_library1 + 1
		elif packets_library1[i].haslayer(Dot11Deauth) == 1:
			Deauth_library1 = Deauth_library1 + 1
		elif packets_library1[i].haslayer(Dot11Disas) == 1:
			Disas_library1 = Disas_library1 + 1
		elif packets_library1[i].haslayer(Dot11ProbeReq) == 1:
			ProbeReq_library1 = ProbeReq_library1 + 1
		elif packets_library1[i].haslayer(Dot11ProbeResp) == 1:
			ProbeResp_library1 = ProbeResp_library1 + 1
		elif packets_library1[i].haslayer(Dot11ReassoReq) == 1:
			ReassoReq_library1 = ReassoReq_library1 + 1
		elif packets_library1[i].haslayer(Dot11ReassoResp) == 1:
			ReassoResp_library1= ReassoResp_library1 + 1
		elif packets_library1[i].haslayer(Dot11ATIM) == 1:
			ATIM_library1 = ATIM_library1 + 1
		else:
			Others_mgmt_library1 = Others_mgmt_library1 + 1

	elif packets_library1[i][Dot11].type == 1:
		Control_library1 = Control_library1 + 1
		if packets_library1[i][Dot11].subtype == 10:
			PS_library1 = PS_library1 + 1
		elif packets_library1[i][Dot11].subtype == 11:
			RTS_library1 = RTS_library1 + 1
		elif packets_library1[i][Dot11].subtype == 12:
			CTS_library1 = CTS_library1 + 1
		elif packets_library1[i][Dot11].subtype == 13:
			Acknowledgement_library1 = Acknowledgement_library1 + 1
		elif packets_library1[i][Dot11].subtype == 14:
			CFEnd_library1 = CFEnd_library1 + 1
		elif packets_library1[i][Dot11].subtype == 15:
			CFEnd_Ack_library1 = CFEnd_Ack_library1 + 1
		else:
			Others_ctl_library1 = Others_ctl_library1 + 1
			
	elif packets_library1[i][Dot11].type == 2:
		Data_library1 = Data_library1 + 1
		if packets_library1[i][Dot11].subtype == 0:
			data_library1 = data_library1 + 1
		elif packets_library1[i][Dot11].subtype == 1:
			data_cf_ack_library1 = data_cf_ack_library1 + 1
		elif packets_library1[i][Dot11].subtype == 2:
			data_cf_poll_library1 = data_cf_poll_library1 + 1
		elif packets_library1[i][Dot11].subtype == 3:
			data_cf_ack_cf_poll_library1 = data_cf_ack_cf_poll_library1 + 1
		elif packets_library1[i][Dot11].subtype == 4:
			null_data_library1 = null_data_library1 + 1
		elif packets_library1[i][Dot11].subtype == 5:
			cf_ack_library1 = cf_ack_library1 + 1
		elif packets_library1[i][Dot11].subtype == 6:
			cf_poll_library1 = cf_poll_library1 + 1
		elif packets_library1[i][Dot11].subtype == 7:
			cf_ack_cf_poll_library1 = cf_ack_cf_poll_library1 + 1
		else: 
			Others_data_library1 = Others_data_library1 + 1

			
print("Management Frames: " + str(Management_library1))
print("Control Frames: " + str(Control_library1))
print("Data Frames: " + str(Data_library1)) 
print("----------------------------------")


print("Beacon Frames: " + str(Beacon_library1))
print("Association Request Frames: " +str(AssoReq_library1))
print("Association Response Frames: " +str(AssoResp_library1))
print("Authentication Frames: "+str(Auth_library1))
print("Deauthentication Frames: "+str(Deauth_library1))
print("Dissociation Frames: "+str(Disas_library1))
print("Probe Request Frames: " +str(ProbeReq_library1))
print("Probe Response Frames: " +str(ProbeResp_library1))
print("Reassociation Request Frames: "+str(ReassoReq_library1))
print("Reassociation Response Frames: "+str(ReassoResp_library1))
print("Announcement traffic indication message: "+str(ATIM_library1))
print("Other Management Frames: "+str(Others_mgmt_library1))
print("----------------------------------")


print("Power Save (PS) Poll Frames: " + str(PS_library1))
print("Request to Send (RTS) Frames: " + str(RTS_library1))
print("Clear to Send (CTS) Frames: " + str(CTS_library1))
print("Acknowledgement Frames: " + str(Acknowledgement_library1))
print("Contention Free (CF)- End Frames: " + str(CFEnd_library1))
print("Contention Free (CF)- End + Ack Frames: " + str(CFEnd_Ack_library1))
print("Other Control Frames: "+str(Others_ctl_library1))
print("----------------------------------")

print("Data frames: "+str(data_library1))
print("Data + CF-Acknowledgement frames: "+str(data_cf_ack_library1))
print("Data + CF-Poll frames: "+str(data_cf_poll_library1))
print("Data + CF-Acknowledgement + CF-Poll frames: "+str(data_cf_ack_cf_poll_library1))
print("Null Data frames: "+str(null_data_library1))
print("CF-Acknowledgement (no data) frames: "+str(cf_ack_library1))
print("CF-Poll (no data) frames: "+str(cf_poll_library1))
print("CF-Acknowledgement + CF-Poll (no data) frames: "+str(cf_ack_cf_poll_library1))
print("Other Data Frames: "+str(Others_data_library1))



main_frame_values_library1 = [Data_library1, Control_library1, Management_library1]
main_frame_type_library1 = ['Data Frame','Control Frame','Management Frame']
cols = ['m', 'r','g']
plt.pie(main_frame_values_library1,labels=main_frame_type_library1,colors=cols,autopct='%1.1f%%')
plt.title('Frame Types in Library: Data Set 1')
plt.show()

mgmt_frame_values_library1 = [Beacon_library1, Auth_library1, ProbeReq_library1, ProbeResp_library1, Others_mgmt_library1]
mgmt_frame_type_library1 = ['Beacon Frame','Authentication Frames','Probe Request Frames','Probe Response Frames','Other']
cols = ['b', 'g','r','c','m']
plt.pie(mgmt_frame_values_library1,labels=mgmt_frame_type_library1,colors=cols,autopct='%1.1f%%')
plt.title('Management Frame Types in Library: Data Set 1')
plt.show()

ctl_frame_values_library1 = [CTS_library1, Acknowledgement_library1, Others_ctl_library1]
ctl_frame_type_library1 = ['Clear to Send (CTS) Frames','Acknowledgement Frames','Other']
cols = ['b', 'g','r']
plt.pie(ctl_frame_values_library1,labels=ctl_frame_type_library1,colors=cols,autopct='%1.1f%%')
plt.title('Control Frame Types in Library: Data Set 1')
plt.show()

data_frame_values_library1 = [data_library1, null_data_library1, Others_data_library1]
data_frame_type_library1 = ['Data Frames','Null Data Frames','Other']
cols = ['b', 'g','r']
plt.pie(data_frame_values_library1,labels=data_frame_type_library1,colors=cols,autopct='%1.1f%%')
plt.title('Data Frame Types in Library: Data Set 1')
plt.show()



## Set 2:
### Clyde: 
print("Set 2:")
from scapy.all import *
packets_clyde2 = rdpcap("/home/mawla/Data_522/clyde_1613.cap")
len(packets_clyde2)
print("----------------------------------")
print("Clyde Building Data:")
print("----------------------------------")
print("Total "+ str(len(packets_clyde2)) + " packets were read")
print("----------------------------------")



Data_clyde2 = 0
Control_clyde2 = 0
Management_clyde2 = 0 

Beacon_clyde2 = 0
AssoReq_clyde2 = 0	
AssoResp_clyde2 = 0
Auth_clyde2 = 0
Deauth_clyde2 = 0
Disas_clyde2 = 0
ProbeReq_clyde2 = 0
ProbeResp_clyde2 = 0
ReassoReq_clyde2 = 0
ReassoResp_clyde2 = 0
ATIM_clyde2 = 0
Others_mgmt_clyde2 = 0


PS_clyde2 = 0
RTS_clyde2 = 0
CTS_clyde2 = 0
Acknowledgement_clyde2 = 0
CFEnd_clyde2 = 0
CFEnd_Ack_clyde2 = 0
Others_ctl_clyde2 = 0

data_clyde2 = 0
data_cf_ack_clyde2 = 0
data_cf_poll_clyde2 = 0
data_cf_ack_cf_poll_clyde2 = 0
null_data_clyde2 = 0
cf_ack_clyde2 = 0
cf_poll_clyde2 = 0
cf_ack_cf_poll_clyde2 = 0
Others_data_clyde2 = 0


for i in range(0, len(packets_clyde2)):
	if packets_clyde2[i][Dot11].type == 0:
		Management_clyde2 = Management_clyde2 + 1
		if packets_clyde2[i].haslayer(Dot11Beacon) == 1:
			Beacon_clyde2 = Beacon_clyde2 + 1
		elif packets_clyde2[i].haslayer(Dot11AssoReq) == 1:
			AssoReq_clyde2 = AssoReq_clyde2 + 1
		elif packets_clyde2[i].haslayer(Dot11AssoResp) == 1:
			AssoResp_clyde2 = AssoResp_clyde2 + 1
		elif packets_clyde2[i].haslayer(Dot11Auth) == 1:
			Auth_clyde2 = Auth_clyde2 + 1
		elif packets_clyde2[i].haslayer(Dot11Deauth) == 1:
			Deauth_clyde2 = Deauth_clyde2 + 1
		elif packets_clyde2[i].haslayer(Dot11Disas) == 1:
			Disas_clyde2 = Disas_clyde2 + 1
		elif packets_clyde2[i].haslayer(Dot11ProbeReq) == 1:
			ProbeReq_clyde2 = ProbeReq_clyde2 + 1
		elif packets_clyde2[i].haslayer(Dot11ProbeResp) == 1:
			ProbeResp_clyde2 = ProbeResp_clyde2 + 1
		elif packets_clyde2[i].haslayer(Dot11ReassoReq) == 1:
			ReassoReq_clyde2 = ReassoReq_clyde2 + 1
		elif packets_clyde2[i].haslayer(Dot11ReassoResp) == 1:
			ReassoResp_clyde2= ReassoResp_clyde2 + 1
		elif packets_clyde2[i].haslayer(Dot11ATIM) == 1:
			ATIM_clyde2 = ATIM_clyde2 + 1
		else:
			Others_mgmt_clyde2 = Others_mgmt_clyde2 + 1

	elif packets_clyde2[i][Dot11].type == 1:
		Control_clyde2 = Control_clyde2 + 1
		if packets_clyde2[i][Dot11].subtype == 10:
			PS_clyde2 = PS_clyde2 + 1
		elif packets_clyde2[i][Dot11].subtype == 11:
			RTS_clyde2 = RTS_clyde2 + 1
		elif packets_clyde2[i][Dot11].subtype == 12:
			CTS_clyde2 = CTS_clyde2 + 1
		elif packets_clyde2[i][Dot11].subtype == 13:
			Acknowledgement_clyde2 = Acknowledgement_clyde2 + 1
		elif packets_clyde2[i][Dot11].subtype == 14:
			CFEnd_clyde2 = CFEnd_clyde2 + 1
		elif packets_clyde2[i][Dot11].subtype == 15:
			CFEnd_Ack_clyde2 = CFEnd_Ack_clyde2 + 1
		else:
			Others_ctl_clyde2 = Others_ctl_clyde2 + 1
			
	elif packets_clyde2[i][Dot11].type == 2:
		Data_clyde2 = Data_clyde2 + 1
		if packets_clyde2[i][Dot11].subtype == 0:
			data_clyde2 = data_clyde2 + 1
		elif packets_clyde2[i][Dot11].subtype == 1:
			data_cf_ack_clyde2 = data_cf_ack_clyde2 + 1
		elif packets_clyde2[i][Dot11].subtype == 2:
			data_cf_poll_clyde2 = data_cf_poll_clyde2 + 1
		elif packets_clyde2[i][Dot11].subtype == 3:
			data_cf_ack_cf_poll_clyde2 = data_cf_ack_cf_poll_clyde2 + 1
		elif packets_clyde2[i][Dot11].subtype == 4:
			null_data_clyde2 = null_data_clyde2 + 1
		elif packets_clyde2[i][Dot11].subtype == 5:
			cf_ack_clyde2 = cf_ack_clyde2 + 1
		elif packets_clyde2[i][Dot11].subtype == 6:
			cf_poll_clyde2 = cf_poll_clyde2 + 1
		elif packets_clyde2[i][Dot11].subtype == 7:
			cf_ack_cf_poll_clyde2 = cf_ack_cf_poll_clyde2 + 1
		else: 
			Others_data_clyde2 = Others_data_clyde2 + 1

			
print("Management Frames: " + str(Management_clyde2))
print("Control Frames: " + str(Control_clyde2))
print("Data Frames: " + str(Data_clyde2)) 
print("----------------------------------")


print("Beacon Frames: " + str(Beacon_clyde2))
print("Association Request Frames: " +str(AssoReq_clyde2))
print("Association Response Frames: " +str(AssoResp_clyde2))
print("Authentication Frames: "+str(Auth_clyde2))
print("Deauthentication Frames: "+str(Deauth_clyde2))
print("Dissociation Frames: "+str(Disas_clyde2))
print("Probe Request Frames: " +str(ProbeReq_clyde2))
print("Probe Response Frames: " +str(ProbeResp_clyde2))
print("Reassociation Request Frames: "+str(ReassoReq_clyde2))
print("Reassociation Response Frames: "+str(ReassoResp_clyde2))
print("Announcement traffic indication message: "+str(ATIM_clyde2))
print("Other Management Frames: "+str(Others_mgmt_clyde2))
print("----------------------------------")


print("Power Save (PS) Poll Frames: " + str(PS_clyde2))
print("Request to Send (RTS) Frames: " + str(RTS_clyde2))
print("Clear to Send (CTS) Frames: " + str(CTS_clyde2))
print("Acknowledgement Frames: " + str(Acknowledgement_clyde2))
print("Contention Free (CF)- End Frames: " + str(CFEnd_clyde2))
print("Contention Free (CF)- End + Ack Frames: " + str(CFEnd_Ack_clyde2))
print("Other Control Frames: "+str(Others_ctl_clyde2))
print("----------------------------------")

print("Data frames: "+str(data_clyde2))
print("Data + CF-Acknowledgement frames: "+str(data_cf_ack_clyde2))
print("Data + CF-Poll frames: "+str(data_cf_poll_clyde2))
print("Data + CF-Acknowledgement + CF-Poll frames: "+str(data_cf_ack_cf_poll_clyde2))
print("Null Data frames: "+str(null_data_clyde2))
print("CF-Acknowledgement (no data) frames: "+str(cf_ack_clyde2))
print("CF-Poll (no data) frames: "+str(cf_poll_clyde2))
print("CF-Acknowledgement + CF-Poll (no data) frames: "+str(cf_ack_cf_poll_clyde2))
print("Other Data Frames: "+str(Others_data_clyde2))
print("----------------------------------")



import matplotlib.pyplot as plt
main_frame_values_clyde2 = [Data_clyde2, Control_clyde2, Management_clyde2]
main_frame_type_clyde2 = ['Data Frame','Control Frame','Management Frame']
cols = ['m', 'r','g']
plt.pie(main_frame_values_clyde2,labels=main_frame_type_clyde2,colors=cols,autopct='%1.1f%%')
plt.title('Frame Types in Clyde Building: Data Set 2')
plt.show()

mgmt_frame_values_clyde2 = [Beacon_clyde2, Auth_clyde2, ProbeReq_clyde2, ProbeResp_clyde2, Others_mgmt_clyde2]
mgmt_frame_type_clyde2 = ['Beacon Frame','Authentication Frames','Probe Request Frames','Probe Response Frames','Other']
cols = ['b', 'g','r','c','m']
plt.pie(mgmt_frame_values_clyde2,labels=mgmt_frame_type_clyde2,colors=cols,autopct='%1.1f%%')
plt.title('Management Frame Types in Clyde Building: Data Set 2')
plt.show()

ctl_frame_values_clyde2 = [CTS_clyde2, Acknowledgement_clyde2, Others_ctl_clyde2]
ctl_frame_type_clyde2 = ['Clear to Send (CTS) Frames','Acknowledgement Frames','Other']
cols = ['b', 'g','r']
plt.pie(ctl_frame_values_clyde2,labels=ctl_frame_type_clyde2,colors=cols,autopct='%1.1f%%')
plt.title('Control Frame Types in Clyde Building: Data Set 2')
plt.show()


data_frame_values_clyde2 = [data_clyde2, null_data_clyde2, Others_data_clyde2]
data_frame_type_clyde2 = ['Data Frames','Null Data Frames','Other']
cols = ['b', 'g','r']
plt.pie(data_frame_values_clyde2,labels=data_frame_type_clyde2,colors=cols,autopct='%1.1f%%')
plt.title('Data Frame Types in Clyde Building: Data Set 1')
plt.show()


### Wilk:

from scapy.all import *
packets_wilk2 = rdpcap("/home/mawla/Data_522/wilk_1648.cap")
len(packets_wilk2)
print("----------------------------------")
print("Wilk Student Center Data:")
print("----------------------------------")
print("Total "+ str(len(packets_wilk2)) + " packets were read")
print("----------------------------------")



Data_wilk2 = 0
Control_wilk2 = 0
Management_wilk2 = 0 

Beacon_wilk2 = 0
AssoReq_wilk2 = 0	
AssoResp_wilk2 = 0
Auth_wilk2 = 0
Deauth_wilk2 = 0
Disas_wilk2 = 0
ProbeReq_wilk2 = 0
ProbeResp_wilk2 = 0
ReassoReq_wilk2 = 0
ReassoResp_wilk2 = 0
ATIM_wilk2 = 0
Others_mgmt_wilk2 = 0


PS_wilk2 = 0
RTS_wilk2 = 0
CTS_wilk2 = 0
Acknowledgement_wilk2 = 0
CFEnd_wilk2 = 0
CFEnd_Ack_wilk2 = 0
Others_ctl_wilk2 = 0

data_wilk2 = 0
data_cf_ack_wilk2 = 0
data_cf_poll_wilk2 = 0
data_cf_ack_cf_poll_wilk2 = 0
null_data_wilk2 = 0
cf_ack_wilk2 = 0
cf_poll_wilk2 = 0
cf_ack_cf_poll_wilk2 = 0
Others_data_wilk2 = 0


for i in range(0, len(packets_wilk2)):
	if packets_wilk2[i][Dot11].type == 0:
		Management_wilk2 = Management_wilk2 + 1
		if packets_wilk2[i].haslayer(Dot11Beacon) == 1:
			Beacon_wilk2 = Beacon_wilk2 + 1
		elif packets_wilk2[i].haslayer(Dot11AssoReq) == 1:
			AssoReq_wilk2 = AssoReq_wilk2 + 1
		elif packets_wilk2[i].haslayer(Dot11AssoResp) == 1:
			AssoResp_wilk2 = AssoResp_wilk2 + 1
		elif packets_wilk2[i].haslayer(Dot11Auth) == 1:
			Auth_wilk2 = Auth_wilk2 + 1
		elif packets_wilk2[i].haslayer(Dot11Deauth) == 1:
			Deauth_wilk2 = Deauth_wilk2 + 1
		elif packets_wilk2[i].haslayer(Dot11Disas) == 1:
			Disas_wilk2 = Disas_wilk2 + 1
		elif packets_wilk2[i].haslayer(Dot11ProbeReq) == 1:
			ProbeReq_wilk2 = ProbeReq_wilk2 + 1
		elif packets_wilk2[i].haslayer(Dot11ProbeResp) == 1:
			ProbeResp_wilk2 = ProbeResp_wilk2 + 1
		elif packets_wilk2[i].haslayer(Dot11ReassoReq) == 1:
			ReassoReq_wilk2 = ReassoReq_wilk2 + 1
		elif packets_wilk2[i].haslayer(Dot11ReassoResp) == 1:
			ReassoResp_wilk2= ReassoResp_wilk2 + 1
		elif packets_wilk2[i].haslayer(Dot11ATIM) == 1:
			ATIM_wilk2 = ATIM_wilk2 + 1
		else:
			Others_mgmt_wilk2 = Others_mgmt_wilk2 + 1

	elif packets_wilk2[i][Dot11].type == 1:
		Control_wilk2 = Control_wilk2 + 1
		if packets_wilk2[i][Dot11].subtype == 10:
			PS_wilk2 = PS_wilk2 + 1
		elif packets_wilk2[i][Dot11].subtype == 11:
			RTS_wilk2 = RTS_wilk2 + 1
		elif packets_wilk2[i][Dot11].subtype == 12:
			CTS_wilk2 = CTS_wilk2 + 1
		elif packets_wilk2[i][Dot11].subtype == 13:
			Acknowledgement_wilk2 = Acknowledgement_wilk2 + 1
		elif packets_wilk2[i][Dot11].subtype == 14:
			CFEnd_wilk2 = CFEnd_wilk2 + 1
		elif packets_wilk2[i][Dot11].subtype == 15:
			CFEnd_Ack_wilk2 = CFEnd_Ack_wilk2 + 1
		else:
			Others_ctl_wilk2 = Others_ctl_wilk2 + 1
			
	elif packets_wilk2[i][Dot11].type == 2:
		Data_wilk2 = Data_wilk2 + 1
		if packets_wilk2[i][Dot11].subtype == 0:
			data_wilk2 = data_wilk2 + 1
		elif packets_wilk2[i][Dot11].subtype == 1:
			data_cf_ack_wilk2 = data_cf_ack_wilk2 + 1
		elif packets_wilk2[i][Dot11].subtype == 2:
			data_cf_poll_wilk2 = data_cf_poll_wilk2 + 1
		elif packets_wilk2[i][Dot11].subtype == 3:
			data_cf_ack_cf_poll_wilk2 = data_cf_ack_cf_poll_wilk2 + 1
		elif packets_wilk2[i][Dot11].subtype == 4:
			null_data_wilk2 = null_data_wilk2 + 1
		elif packets_wilk2[i][Dot11].subtype == 5:
			cf_ack_wilk2 = cf_ack_wilk2 + 1
		elif packets_wilk2[i][Dot11].subtype == 6:
			cf_poll_wilk2 = cf_poll_wilk2 + 1
		elif packets_wilk2[i][Dot11].subtype == 7:
			cf_ack_cf_poll_wilk2 = cf_ack_cf_poll_wilk2 + 1
		else: 
			Others_data_wilk2 = Others_data_wilk2 + 1

			
print("Management Frames: " + str(Management_wilk2))
print("Control Frames: " + str(Control_wilk2))
print("Data Frames: " + str(Data_wilk2)) 
print("----------------------------------")


print("Beacon Frames: " + str(Beacon_wilk2))
print("Association Request Frames: " +str(AssoReq_wilk2))
print("Association Response Frames: " +str(AssoResp_wilk2))
print("Authentication Frames: "+str(Auth_wilk2))
print("Deauthentication Frames: "+str(Deauth_wilk2))
print("Dissociation Frames: "+str(Disas_wilk2))
print("Probe Request Frames: " +str(ProbeReq_wilk2))
print("Probe Response Frames: " +str(ProbeResp_wilk2))
print("Reassociation Request Frames: "+str(ReassoReq_wilk2))
print("Reassociation Response Frames: "+str(ReassoResp_wilk2))
print("Announcement traffic indication message: "+str(ATIM_wilk2))
print("Other Management Frames: "+str(Others_mgmt_wilk2))
print("----------------------------------")


print("Power Save (PS) Poll Frames: " + str(PS_wilk2))
print("Request to Send (RTS) Frames: " + str(RTS_wilk2))
print("Clear to Send (CTS) Frames: " + str(CTS_wilk2))
print("Acknowledgement Frames: " + str(Acknowledgement_wilk2))
print("Contention Free (CF)- End Frames: " + str(CFEnd_wilk2))
print("Contention Free (CF)- End + Ack Frames: " + str(CFEnd_Ack_wilk2))
print("Other Control Frames: "+str(Others_ctl_wilk2))
print("----------------------------------")

print("Data frames: "+str(data_wilk2))
print("Data + CF-Acknowledgement frames: "+str(data_cf_ack_wilk2))
print("Data + CF-Poll frames: "+str(data_cf_poll_wilk2))
print("Data + CF-Acknowledgement + CF-Poll frames: "+str(data_cf_ack_cf_poll_wilk2))
print("Null Data frames: "+str(null_data_wilk2))
print("CF-Acknowledgement (no data) frames: "+str(cf_ack_wilk2))
print("CF-Poll (no data) frames: "+str(cf_poll_wilk2))
print("CF-Acknowledgement + CF-Poll (no data) frames: "+str(cf_ack_cf_poll_wilk2))
print("Other Data Frames: "+str(Others_data_wilk2))

main_frame_values_wilk2 = [Data_wilk2, Control_wilk2, Management_wilk2]
main_frame_type_wilk2 = ['Data Frame','Control Frame','Management Frame']
cols = ['m', 'r','g']
plt.pie(main_frame_values_wilk2,labels=main_frame_type_wilk2,colors=cols,autopct='%1.1f%%')
plt.title('Frame Types in Wilk Student Center: Data Set 2')
plt.show()


mgmt_frame_values_wilk2 = [Beacon_wilk2, Auth_wilk2, ProbeReq_wilk2, ProbeResp_wilk2, Others_mgmt_wilk2]
mgmt_frame_type_wilk2 = ['Beacon Frame','Authentication Frames','Probe Request Frames','Probe Response Frames','Other']
cols = ['b', 'g','r','c','m']
plt.pie(mgmt_frame_values_wilk2,labels=mgmt_frame_type_wilk2,colors=cols,autopct='%1.1f%%')
plt.title('Management Frame Types in Wilk Student Center Building: Data Set 2')
plt.show()

ctl_frame_values_wilk2 = [CTS_wilk2, Acknowledgement_wilk2, Others_ctl_wilk2]
ctl_frame_type_wilk2 = ['Clear to Send (CTS) Frames','Acknowledgement Frames','Other']
cols = ['b', 'g','r']
plt.pie(ctl_frame_values_wilk2,labels=ctl_frame_type_wilk2,colors=cols,autopct='%1.1f%%')
plt.title('Control Frame Types in Wilk Student Center: Data Set 2')
plt.show()

data_frame_values_wilk2 = [data_wilk2, null_data_wilk2, Others_data_wilk2]
data_frame_type_wilk2 = ['Data Frames','Null Data Frames','Other']
cols = ['b', 'g','r']
plt.pie(data_frame_values_wilk2,labels=data_frame_type_wilk2,colors=cols,autopct='%1.1f%%')
plt.title('Data Frame Types in Wilk Student Center: Data Set 2')
plt.show()


### library: 

from scapy.all import *
packets_library2 = rdpcap("/home/mawla/Data_522/library_1630.cap")
len(packets_library2)
print("----------------------------------")
print("Library Data:")
print("----------------------------------")
print("Total "+ str(len(packets_library2)) + " packets were read")
print("----------------------------------")



Data_library2 = 0
Control_library2 = 0
Management_library2 = 0 

Beacon_library2 = 0
AssoReq_library2 = 0	
AssoResp_library2 = 0
Auth_library2 = 0
Deauth_library2 = 0
Disas_library2 = 0
ProbeReq_library2 = 0
ProbeResp_library2 = 0
ReassoReq_library2 = 0
ReassoResp_library2 = 0
ATIM_library2 = 0
Others_mgmt_library2 = 0


PS_library2 = 0
RTS_library2 = 0
CTS_library2 = 0
Acknowledgement_library2 = 0
CFEnd_library2 = 0
CFEnd_Ack_library2 = 0
Others_ctl_library2 = 0

data_library2 = 0
data_cf_ack_library2 = 0
data_cf_poll_library2 = 0
data_cf_ack_cf_poll_library2 = 0
null_data_library2 = 0
cf_ack_library2 = 0
cf_poll_library2 = 0
cf_ack_cf_poll_library2 = 0
Others_data_library2 = 0


for i in range(0, len(packets_library2)):
	if packets_library2[i][Dot11].type == 0:
		Management_library2 = Management_library2 + 1
		if packets_library2[i].haslayer(Dot11Beacon) == 1:
			Beacon_library2 = Beacon_library2 + 1
		elif packets_library2[i].haslayer(Dot11AssoReq) == 1:
			AssoReq_library2 = AssoReq_library2 + 1
		elif packets_library2[i].haslayer(Dot11AssoResp) == 1:
			AssoResp_library2 = AssoResp_library2 + 1
		elif packets_library2[i].haslayer(Dot11Auth) == 1:
			Auth_library2 = Auth_library2 + 1
		elif packets_library2[i].haslayer(Dot11Deauth) == 1:
			Deauth_library2 = Deauth_library2 + 1
		elif packets_library2[i].haslayer(Dot11Disas) == 1:
			Disas_library2 = Disas_library2 + 1
		elif packets_library2[i].haslayer(Dot11ProbeReq) == 1:
			ProbeReq_library2 = ProbeReq_library2 + 1
		elif packets_library2[i].haslayer(Dot11ProbeResp) == 1:
			ProbeResp_library2 = ProbeResp_library2 + 1
		elif packets_library2[i].haslayer(Dot11ReassoReq) == 1:
			ReassoReq_library2 = ReassoReq_library2 + 1
		elif packets_library2[i].haslayer(Dot11ReassoResp) == 1:
			ReassoResp_library2= ReassoResp_library2 + 1
		elif packets_library2[i].haslayer(Dot11ATIM) == 1:
			ATIM_library2 = ATIM_library2 + 1
		else:
			Others_mgmt_library2 = Others_mgmt_library2 + 1

	elif packets_library2[i][Dot11].type == 1:
		Control_library2 = Control_library2 + 1
		if packets_library2[i][Dot11].subtype == 10:
			PS_library2 = PS_library2 + 1
		elif packets_library2[i][Dot11].subtype == 11:
			RTS_library2 = RTS_library2 + 1
		elif packets_library2[i][Dot11].subtype == 12:
			CTS_library2 = CTS_library2 + 1
		elif packets_library2[i][Dot11].subtype == 13:
			Acknowledgement_library2 = Acknowledgement_library2 + 1
		elif packets_library2[i][Dot11].subtype == 14:
			CFEnd_library2 = CFEnd_library2 + 1
		elif packets_library2[i][Dot11].subtype == 15:
			CFEnd_Ack_library2 = CFEnd_Ack_library2 + 1
		else:
			Others_ctl_library2 = Others_ctl_library2 + 1
			
	elif packets_library2[i][Dot11].type == 2:
		Data_library2 = Data_library2 + 1
		if packets_library2[i][Dot11].subtype == 0:
			data_library2 = data_library2 + 1
		elif packets_library2[i][Dot11].subtype == 1:
			data_cf_ack_library2 = data_cf_ack_library2 + 1
		elif packets_library2[i][Dot11].subtype == 2:
			data_cf_poll_library2 = data_cf_poll_library2 + 1
		elif packets_library2[i][Dot11].subtype == 3:
			data_cf_ack_cf_poll_library2 = data_cf_ack_cf_poll_library2 + 1
		elif packets_library2[i][Dot11].subtype == 4:
			null_data_library2 = null_data_library2 + 1
		elif packets_library2[i][Dot11].subtype == 5:
			cf_ack_library2 = cf_ack_library2 + 1
		elif packets_library2[i][Dot11].subtype == 6:
			cf_poll_library2 = cf_poll_library2 + 1
		elif packets_library2[i][Dot11].subtype == 7:
			cf_ack_cf_poll_library2 = cf_ack_cf_poll_library2 + 1
		else: 
			Others_data_library2 = Others_data_library2 + 1

			
print("Management Frames: " + str(Management_library2))
print("Control Frames: " + str(Control_library2))
print("Data Frames: " + str(Data_library2)) 
print("----------------------------------")


print("Beacon Frames: " + str(Beacon_library2))
print("Association Request Frames: " +str(AssoReq_library2))
print("Association Response Frames: " +str(AssoResp_library2))
print("Authentication Frames: "+str(Auth_library2))
print("Deauthentication Frames: "+str(Deauth_library2))
print("Dissociation Frames: "+str(Disas_library2))
print("Probe Request Frames: " +str(ProbeReq_library2))
print("Probe Response Frames: " +str(ProbeResp_library2))
print("Reassociation Request Frames: "+str(ReassoReq_library2))
print("Reassociation Response Frames: "+str(ReassoResp_library2))
print("Announcement traffic indication message: "+str(ATIM_library2))
print("Other Management Frames: "+str(Others_mgmt_library2))
print("----------------------------------")


print("Power Save (PS) Poll Frames: " + str(PS_library2))
print("Request to Send (RTS) Frames: " + str(RTS_library2))
print("Clear to Send (CTS) Frames: " + str(CTS_library2))
print("Acknowledgement Frames: " + str(Acknowledgement_library2))
print("Contention Free (CF)- End Frames: " + str(CFEnd_library2))
print("Contention Free (CF)- End + Ack Frames: " + str(CFEnd_Ack_library2))
print("Other Control Frames: "+str(Others_ctl_library2))
print("----------------------------------")

print("Data frames: "+str(data_library2))
print("Data + CF-Acknowledgement frames: "+str(data_cf_ack_library2))
print("Data + CF-Poll frames: "+str(data_cf_poll_library2))
print("Data + CF-Acknowledgement + CF-Poll frames: "+str(data_cf_ack_cf_poll_library2))
print("Null Data frames: "+str(null_data_library2))
print("CF-Acknowledgement (no data) frames: "+str(cf_ack_library2))
print("CF-Poll (no data) frames: "+str(cf_poll_library2))
print("CF-Acknowledgement + CF-Poll (no data) frames: "+str(cf_ack_cf_poll_library2))
print("Other Data Frames: "+str(Others_data_library2))



main_frame_values_library2 = [Data_library2, Control_library2, Management_library2]
main_frame_type_library2 = ['Data Frame','Control Frame','Management Frame']
cols = ['m', 'r','g']
plt.pie(main_frame_values_library2,labels=main_frame_type_library2,colors=cols,autopct='%1.1f%%')
plt.title('Frame Types in Library: Data Set 2')
plt.show()

mgmt_frame_values_library2 = [Beacon_library2, Auth_library2, ProbeReq_library2, ProbeResp_library2, Others_mgmt_library2]
mgmt_frame_type_library2 = ['Beacon Frame','Authentication Frames','Probe Request Frames','Probe Response Frames','Other']
cols = ['b', 'g','r','c','m']
plt.pie(mgmt_frame_values_library2,labels=mgmt_frame_type_library2,colors=cols,autopct='%1.1f%%')
plt.title('Management Frame Types in Library: Data Set 2')
plt.show()

ctl_frame_values_library2 = [CTS_library2, Acknowledgement_library2, Others_ctl_library2]
ctl_frame_type_library2 = ['Clear to Send (CTS) Frames','Acknowledgement Frames','Other']
cols = ['b', 'g','r']
plt.pie(ctl_frame_values_library2,labels=ctl_frame_type_library2,colors=cols,autopct='%1.1f%%')
plt.title('Control Frame Types in Library: Data Set 2')
plt.show()

data_frame_values_library2 = [data_library2, null_data_library2, Others_data_library2]
data_frame_type_library2 = ['Data Frames','Null Data Frames','Other']
cols = ['b', 'g','r']
plt.pie(data_frame_values_library2,labels=data_frame_type_library2,colors=cols,autopct='%1.1f%%')
plt.title('Data Frame Types in Library: Data Set 2')
plt.show()


## Set 3:
### Clyde: 
print("Set 3:")
from scapy.all import *
packets_clyde3 = rdpcap("/home/mawla/Data_522/clyde_1746.cap")
len(packets_clyde3)
print("----------------------------------")
print("Clyde Building Data:")
print("----------------------------------")
print("Total "+ str(len(packets_clyde3)) + " packets were read")
print("----------------------------------")



Data_clyde3 = 0
Control_clyde3 = 0
Management_clyde3 = 0 

Beacon_clyde3 = 0
AssoReq_clyde3 = 0	
AssoResp_clyde3 = 0
Auth_clyde3 = 0
Deauth_clyde3 = 0
Disas_clyde3 = 0
ProbeReq_clyde3 = 0
ProbeResp_clyde3 = 0
ReassoReq_clyde3 = 0
ReassoResp_clyde3 = 0
ATIM_clyde3 = 0
Others_mgmt_clyde3 = 0


PS_clyde3 = 0
RTS_clyde3 = 0
CTS_clyde3 = 0
Acknowledgement_clyde3 = 0
CFEnd_clyde3 = 0
CFEnd_Ack_clyde3 = 0
Others_ctl_clyde3 = 0

data_clyde3 = 0
data_cf_ack_clyde3 = 0
data_cf_poll_clyde3 = 0
data_cf_ack_cf_poll_clyde3 = 0
null_data_clyde3 = 0
cf_ack_clyde3 = 0
cf_poll_clyde3 = 0
cf_ack_cf_poll_clyde3 = 0
Others_data_clyde3 = 0


for i in range(0, len(packets_clyde3)):
	if packets_clyde3[i][Dot11].type == 0:
		Management_clyde3 = Management_clyde3 + 1
		if packets_clyde3[i].haslayer(Dot11Beacon) == 1:
			Beacon_clyde3 = Beacon_clyde3 + 1
		elif packets_clyde3[i].haslayer(Dot11AssoReq) == 1:
			AssoReq_clyde3 = AssoReq_clyde3 + 1
		elif packets_clyde3[i].haslayer(Dot11AssoResp) == 1:
			AssoResp_clyde3 = AssoResp_clyde3 + 1
		elif packets_clyde3[i].haslayer(Dot11Auth) == 1:
			Auth_clyde3 = Auth_clyde3 + 1
		elif packets_clyde3[i].haslayer(Dot11Deauth) == 1:
			Deauth_clyde3 = Deauth_clyde3 + 1
		elif packets_clyde3[i].haslayer(Dot11Disas) == 1:
			Disas_clyde3 = Disas_clyde3 + 1
		elif packets_clyde3[i].haslayer(Dot11ProbeReq) == 1:
			ProbeReq_clyde3 = ProbeReq_clyde3 + 1
		elif packets_clyde3[i].haslayer(Dot11ProbeResp) == 1:
			ProbeResp_clyde3 = ProbeResp_clyde3 + 1
		elif packets_clyde3[i].haslayer(Dot11ReassoReq) == 1:
			ReassoReq_clyde3 = ReassoReq_clyde3 + 1
		elif packets_clyde3[i].haslayer(Dot11ReassoResp) == 1:
			ReassoResp_clyde3= ReassoResp_clyde3 + 1
		elif packets_clyde3[i].haslayer(Dot11ATIM) == 1:
			ATIM_clyde3 = ATIM_clyde3 + 1
		else:
			Others_mgmt_clyde3 = Others_mgmt_clyde3 + 1

	elif packets_clyde3[i][Dot11].type == 1:
		Control_clyde3 = Control_clyde3 + 1
		if packets_clyde3[i][Dot11].subtype == 10:
			PS_clyde3 = PS_clyde3 + 1
		elif packets_clyde3[i][Dot11].subtype == 11:
			RTS_clyde3 = RTS_clyde3 + 1
		elif packets_clyde3[i][Dot11].subtype == 12:
			CTS_clyde3 = CTS_clyde3 + 1
		elif packets_clyde3[i][Dot11].subtype == 13:
			Acknowledgement_clyde3 = Acknowledgement_clyde3 + 1
		elif packets_clyde3[i][Dot11].subtype == 14:
			CFEnd_clyde3 = CFEnd_clyde3 + 1
		elif packets_clyde3[i][Dot11].subtype == 15:
			CFEnd_Ack_clyde3 = CFEnd_Ack_clyde3 + 1
		else:
			Others_ctl_clyde3 = Others_ctl_clyde3 + 1
			
	elif packets_clyde3[i][Dot11].type == 2:
		Data_clyde3 = Data_clyde3 + 1
		if packets_clyde3[i][Dot11].subtype == 0:
			data_clyde3 = data_clyde3 + 1
		elif packets_clyde3[i][Dot11].subtype == 1:
			data_cf_ack_clyde3 = data_cf_ack_clyde3 + 1
		elif packets_clyde3[i][Dot11].subtype == 2:
			data_cf_poll_clyde3 = data_cf_poll_clyde3 + 1
		elif packets_clyde3[i][Dot11].subtype == 3:
			data_cf_ack_cf_poll_clyde3 = data_cf_ack_cf_poll_clyde3 + 1
		elif packets_clyde3[i][Dot11].subtype == 4:
			null_data_clyde3 = null_data_clyde3 + 1
		elif packets_clyde3[i][Dot11].subtype == 5:
			cf_ack_clyde3 = cf_ack_clyde3 + 1
		elif packets_clyde3[i][Dot11].subtype == 6:
			cf_poll_clyde3 = cf_poll_clyde3 + 1
		elif packets_clyde3[i][Dot11].subtype == 7:
			cf_ack_cf_poll_clyde3 = cf_ack_cf_poll_clyde3 + 1
		else: 
			Others_data_clyde3 = Others_data_clyde3 + 1

			
print("Management Frames: " + str(Management_clyde3))
print("Control Frames: " + str(Control_clyde3))
print("Data Frames: " + str(Data_clyde3)) 
print("----------------------------------")


print("Beacon Frames: " + str(Beacon_clyde3))
print("Association Request Frames: " +str(AssoReq_clyde3))
print("Association Response Frames: " +str(AssoResp_clyde3))
print("Authentication Frames: "+str(Auth_clyde3))
print("Deauthentication Frames: "+str(Deauth_clyde3))
print("Dissociation Frames: "+str(Disas_clyde3))
print("Probe Request Frames: " +str(ProbeReq_clyde3))
print("Probe Response Frames: " +str(ProbeResp_clyde3))
print("Reassociation Request Frames: "+str(ReassoReq_clyde3))
print("Reassociation Response Frames: "+str(ReassoResp_clyde3))
print("Announcement traffic indication message: "+str(ATIM_clyde3))
print("Other Management Frames: "+str(Others_mgmt_clyde3))
print("----------------------------------")


print("Power Save (PS) Poll Frames: " + str(PS_clyde3))
print("Request to Send (RTS) Frames: " + str(RTS_clyde3))
print("Clear to Send (CTS) Frames: " + str(CTS_clyde3))
print("Acknowledgement Frames: " + str(Acknowledgement_clyde3))
print("Contention Free (CF)- End Frames: " + str(CFEnd_clyde3))
print("Contention Free (CF)- End + Ack Frames: " + str(CFEnd_Ack_clyde3))
print("Other Control Frames: "+str(Others_ctl_clyde3))
print("----------------------------------")

print("Data frames: "+str(data_clyde3))
print("Data + CF-Acknowledgement frames: "+str(data_cf_ack_clyde3))
print("Data + CF-Poll frames: "+str(data_cf_poll_clyde3))
print("Data + CF-Acknowledgement + CF-Poll frames: "+str(data_cf_ack_cf_poll_clyde3))
print("Null Data frames: "+str(null_data_clyde3))
print("CF-Acknowledgement (no data) frames: "+str(cf_ack_clyde3))
print("CF-Poll (no data) frames: "+str(cf_poll_clyde3))
print("CF-Acknowledgement + CF-Poll (no data) frames: "+str(cf_ack_cf_poll_clyde3))
print("Other Data Frames: "+str(Others_data_clyde3))
print("----------------------------------")



import matplotlib.pyplot as plt
main_frame_values_clyde3 = [Data_clyde3, Control_clyde3, Management_clyde3]
main_frame_type_clyde3 = ['Data Frame','Control Frame','Management Frame']
cols = ['m', 'r','g']
plt.pie(main_frame_values_clyde3,labels=main_frame_type_clyde3,colors=cols,autopct='%1.1f%%')
plt.title('Frame Types in Clyde Building: Data Set 3')
plt.show()

mgmt_frame_values_clyde3 = [Beacon_clyde3, Auth_clyde3, ProbeReq_clyde3, ProbeResp_clyde3, Others_mgmt_clyde3]
mgmt_frame_type_clyde3 = ['Beacon Frame','Authentication Frames','Probe Request Frames','Probe Response Frames','Other']
cols = ['b', 'g','r','c','m']
plt.pie(mgmt_frame_values_clyde3,labels=mgmt_frame_type_clyde3,colors=cols,autopct='%1.1f%%')
plt.title('Management Frame Types in Clyde Building: Data Set 3')
plt.show()

ctl_frame_values_clyde3 = [CTS_clyde3, Acknowledgement_clyde3, Others_ctl_clyde3]
ctl_frame_type_clyde3 = ['Clear to Send (CTS) Frames','Acknowledgement Frames','Other']
cols = ['b', 'g','r']
plt.pie(ctl_frame_values_clyde3,labels=ctl_frame_type_clyde3,colors=cols,autopct='%1.1f%%')
plt.title('Control Frame Types in Clyde Building: Data Set 3')
plt.show()


data_frame_values_clyde3 = [data_clyde3, null_data_clyde3, Others_data_clyde3]
data_frame_type_clyde3 = ['Data Frames','Null Data Frames','Other']
cols = ['b', 'g','r']
plt.pie(data_frame_values_clyde3,labels=data_frame_type_clyde3,colors=cols,autopct='%1.1f%%')
plt.title('Data Frame Types in Clyde Building: Data Set 3')
plt.show()


### Wilk:

from scapy.all import *
packets_wilk3 = rdpcap("/home/mawla/Data_522/wilk_1713.cap")
len(packets_wilk3)
print("----------------------------------")
print("Wilk Student Center Data:")
print("----------------------------------")
print("Total "+ str(len(packets_wilk3)) + " packets were read")
print("----------------------------------")



Data_wilk3 = 0
Control_wilk3 = 0
Management_wilk3 = 0 

Beacon_wilk3 = 0
AssoReq_wilk3 = 0	
AssoResp_wilk3 = 0
Auth_wilk3 = 0
Deauth_wilk3 = 0
Disas_wilk3 = 0
ProbeReq_wilk3 = 0
ProbeResp_wilk3 = 0
ReassoReq_wilk3 = 0
ReassoResp_wilk3 = 0
ATIM_wilk3 = 0
Others_mgmt_wilk3 = 0


PS_wilk3 = 0
RTS_wilk3 = 0
CTS_wilk3 = 0
Acknowledgement_wilk3 = 0
CFEnd_wilk3 = 0
CFEnd_Ack_wilk3 = 0
Others_ctl_wilk3 = 0

data_wilk3 = 0
data_cf_ack_wilk3 = 0
data_cf_poll_wilk3 = 0
data_cf_ack_cf_poll_wilk3 = 0
null_data_wilk3 = 0
cf_ack_wilk3 = 0
cf_poll_wilk3 = 0
cf_ack_cf_poll_wilk3 = 0
Others_data_wilk3 = 0


for i in range(0, len(packets_wilk3)):
	if packets_wilk3[i][Dot11].type == 0:
		Management_wilk3 = Management_wilk3 + 1
		if packets_wilk3[i].haslayer(Dot11Beacon) == 1:
			Beacon_wilk3 = Beacon_wilk3 + 1
		elif packets_wilk3[i].haslayer(Dot11AssoReq) == 1:
			AssoReq_wilk3 = AssoReq_wilk3 + 1
		elif packets_wilk3[i].haslayer(Dot11AssoResp) == 1:
			AssoResp_wilk3 = AssoResp_wilk3 + 1
		elif packets_wilk3[i].haslayer(Dot11Auth) == 1:
			Auth_wilk3 = Auth_wilk3 + 1
		elif packets_wilk3[i].haslayer(Dot11Deauth) == 1:
			Deauth_wilk3 = Deauth_wilk3 + 1
		elif packets_wilk3[i].haslayer(Dot11Disas) == 1:
			Disas_wilk3 = Disas_wilk3 + 1
		elif packets_wilk3[i].haslayer(Dot11ProbeReq) == 1:
			ProbeReq_wilk3 = ProbeReq_wilk3 + 1
		elif packets_wilk3[i].haslayer(Dot11ProbeResp) == 1:
			ProbeResp_wilk3 = ProbeResp_wilk3 + 1
		elif packets_wilk3[i].haslayer(Dot11ReassoReq) == 1:
			ReassoReq_wilk3 = ReassoReq_wilk3 + 1
		elif packets_wilk3[i].haslayer(Dot11ReassoResp) == 1:
			ReassoResp_wilk3= ReassoResp_wilk3 + 1
		elif packets_wilk3[i].haslayer(Dot11ATIM) == 1:
			ATIM_wilk3 = ATIM_wilk3 + 1
		else:
			Others_mgmt_wilk3 = Others_mgmt_wilk3 + 1

	elif packets_wilk3[i][Dot11].type == 1:
		Control_wilk3 = Control_wilk3 + 1
		if packets_wilk3[i][Dot11].subtype == 10:
			PS_wilk3 = PS_wilk3 + 1
		elif packets_wilk3[i][Dot11].subtype == 11:
			RTS_wilk3 = RTS_wilk3 + 1
		elif packets_wilk3[i][Dot11].subtype == 12:
			CTS_wilk3 = CTS_wilk3 + 1
		elif packets_wilk3[i][Dot11].subtype == 13:
			Acknowledgement_wilk3 = Acknowledgement_wilk3 + 1
		elif packets_wilk3[i][Dot11].subtype == 14:
			CFEnd_wilk3 = CFEnd_wilk3 + 1
		elif packets_wilk3[i][Dot11].subtype == 15:
			CFEnd_Ack_wilk3 = CFEnd_Ack_wilk3 + 1
		else:
			Others_ctl_wilk3 = Others_ctl_wilk3 + 1
			
	elif packets_wilk3[i][Dot11].type == 2:
		Data_wilk3 = Data_wilk3 + 1
		if packets_wilk3[i][Dot11].subtype == 0:
			data_wilk3 = data_wilk3 + 1
		elif packets_wilk3[i][Dot11].subtype == 1:
			data_cf_ack_wilk3 = data_cf_ack_wilk3 + 1
		elif packets_wilk3[i][Dot11].subtype == 2:
			data_cf_poll_wilk3 = data_cf_poll_wilk3 + 1
		elif packets_wilk3[i][Dot11].subtype == 3:
			data_cf_ack_cf_poll_wilk3 = data_cf_ack_cf_poll_wilk3 + 1
		elif packets_wilk3[i][Dot11].subtype == 4:
			null_data_wilk3 = null_data_wilk3 + 1
		elif packets_wilk3[i][Dot11].subtype == 5:
			cf_ack_wilk3 = cf_ack_wilk3 + 1
		elif packets_wilk3[i][Dot11].subtype == 6:
			cf_poll_wilk3 = cf_poll_wilk3 + 1
		elif packets_wilk3[i][Dot11].subtype == 7:
			cf_ack_cf_poll_wilk3 = cf_ack_cf_poll_wilk3 + 1
		else: 
			Others_data_wilk3 = Others_data_wilk3 + 1

			
print("Management Frames: " + str(Management_wilk3))
print("Control Frames: " + str(Control_wilk3))
print("Data Frames: " + str(Data_wilk3)) 
print("----------------------------------")


print("Beacon Frames: " + str(Beacon_wilk3))
print("Association Request Frames: " +str(AssoReq_wilk3))
print("Association Response Frames: " +str(AssoResp_wilk3))
print("Authentication Frames: "+str(Auth_wilk3))
print("Deauthentication Frames: "+str(Deauth_wilk3))
print("Dissociation Frames: "+str(Disas_wilk3))
print("Probe Request Frames: " +str(ProbeReq_wilk3))
print("Probe Response Frames: " +str(ProbeResp_wilk3))
print("Reassociation Request Frames: "+str(ReassoReq_wilk3))
print("Reassociation Response Frames: "+str(ReassoResp_wilk3))
print("Announcement traffic indication message: "+str(ATIM_wilk3))
print("Other Management Frames: "+str(Others_mgmt_wilk3))
print("----------------------------------")


print("Power Save (PS) Poll Frames: " + str(PS_wilk3))
print("Request to Send (RTS) Frames: " + str(RTS_wilk3))
print("Clear to Send (CTS) Frames: " + str(CTS_wilk3))
print("Acknowledgement Frames: " + str(Acknowledgement_wilk3))
print("Contention Free (CF)- End Frames: " + str(CFEnd_wilk3))
print("Contention Free (CF)- End + Ack Frames: " + str(CFEnd_Ack_wilk3))
print("Other Control Frames: "+str(Others_ctl_wilk3))
print("----------------------------------")

print("Data frames: "+str(data_wilk3))
print("Data + CF-Acknowledgement frames: "+str(data_cf_ack_wilk3))
print("Data + CF-Poll frames: "+str(data_cf_poll_wilk3))
print("Data + CF-Acknowledgement + CF-Poll frames: "+str(data_cf_ack_cf_poll_wilk3))
print("Null Data frames: "+str(null_data_wilk3))
print("CF-Acknowledgement (no data) frames: "+str(cf_ack_wilk3))
print("CF-Poll (no data) frames: "+str(cf_poll_wilk3))
print("CF-Acknowledgement + CF-Poll (no data) frames: "+str(cf_ack_cf_poll_wilk3))
print("Other Data Frames: "+str(Others_data_wilk3))

main_frame_values_wilk3 = [Data_wilk3, Control_wilk3, Management_wilk3]
main_frame_type_wilk3 = ['Data Frame','Control Frame','Management Frame']
cols = ['m', 'r','g']
plt.pie(main_frame_values_wilk3,labels=main_frame_type_wilk3,colors=cols,autopct='%1.1f%%')
plt.title('Frame Types in Wilk Student Center: Data Set 3')
plt.show()


mgmt_frame_values_wilk3 = [Beacon_wilk3, Auth_wilk3, ProbeReq_wilk3, ProbeResp_wilk3, Others_mgmt_wilk3]
mgmt_frame_type_wilk3 = ['Beacon Frame','Authentication Frames','Probe Request Frames','Probe Response Frames','Other']
cols = ['b', 'g','r','c','m']
plt.pie(mgmt_frame_values_wilk3,labels=mgmt_frame_type_wilk3,colors=cols,autopct='%1.1f%%')
plt.title('Management Frame Types in Wilk Student Center Building: Data Set 3')
plt.show()

ctl_frame_values_wilk3 = [CTS_wilk3, Acknowledgement_wilk3, Others_ctl_wilk3]
ctl_frame_type_wilk3 = ['Clear to Send (CTS) Frames','Acknowledgement Frames','Other']
cols = ['b', 'g','r']
plt.pie(ctl_frame_values_wilk3,labels=ctl_frame_type_wilk3,colors=cols,autopct='%1.1f%%')
plt.title('Control Frame Types in Wilk Student Center: Data Set 3')
plt.show()

data_frame_values_wilk3 = [data_wilk3, null_data_wilk3, Others_data_wilk3]
data_frame_type_wilk3 = ['Data Frames','Null Data Frames','Other']
cols = ['b', 'g','r']
plt.pie(data_frame_values_wilk3,labels=data_frame_type_wilk3,colors=cols,autopct='%1.1f%%')
plt.title('Data Frame Types in Wilk Student Center: Data Set 3')
plt.show()


### library: 

from scapy.all import *
packets_library3 = rdpcap("/home/mawla/Data_522/library_1736.cap")
len(packets_library3)
print("----------------------------------")
print("Library Data:")
print("----------------------------------")
print("Total "+ str(len(packets_library3)) + " packets were read")
print("----------------------------------")



Data_library3 = 0
Control_library3 = 0
Management_library3 = 0 

Beacon_library3 = 0
AssoReq_library3 = 0	
AssoResp_library3 = 0
Auth_library3 = 0
Deauth_library3 = 0
Disas_library3 = 0
ProbeReq_library3 = 0
ProbeResp_library3 = 0
ReassoReq_library3 = 0
ReassoResp_library3 = 0
ATIM_library3 = 0
Others_mgmt_library3 = 0


PS_library3 = 0
RTS_library3 = 0
CTS_library3 = 0
Acknowledgement_library3 = 0
CFEnd_library3 = 0
CFEnd_Ack_library3 = 0
Others_ctl_library3 = 0

data_library3 = 0
data_cf_ack_library3 = 0
data_cf_poll_library3 = 0
data_cf_ack_cf_poll_library3 = 0
null_data_library3 = 0
cf_ack_library3 = 0
cf_poll_library3 = 0
cf_ack_cf_poll_library3 = 0
Others_data_library3 = 0


for i in range(0, len(packets_library3)):
	if packets_library3[i][Dot11].type == 0:
		Management_library3 = Management_library3 + 1
		if packets_library3[i].haslayer(Dot11Beacon) == 1:
			Beacon_library3 = Beacon_library3 + 1
		elif packets_library3[i].haslayer(Dot11AssoReq) == 1:
			AssoReq_library3 = AssoReq_library3 + 1
		elif packets_library3[i].haslayer(Dot11AssoResp) == 1:
			AssoResp_library3 = AssoResp_library3 + 1
		elif packets_library3[i].haslayer(Dot11Auth) == 1:
			Auth_library3 = Auth_library3 + 1
		elif packets_library3[i].haslayer(Dot11Deauth) == 1:
			Deauth_library3 = Deauth_library3 + 1
		elif packets_library3[i].haslayer(Dot11Disas) == 1:
			Disas_library3 = Disas_library3 + 1
		elif packets_library3[i].haslayer(Dot11ProbeReq) == 1:
			ProbeReq_library3 = ProbeReq_library3 + 1
		elif packets_library3[i].haslayer(Dot11ProbeResp) == 1:
			ProbeResp_library3 = ProbeResp_library3 + 1
		elif packets_library3[i].haslayer(Dot11ReassoReq) == 1:
			ReassoReq_library3 = ReassoReq_library3 + 1
		elif packets_library3[i].haslayer(Dot11ReassoResp) == 1:
			ReassoResp_library3= ReassoResp_library3 + 1
		elif packets_library3[i].haslayer(Dot11ATIM) == 1:
			ATIM_library3 = ATIM_library3 + 1
		else:
			Others_mgmt_library3 = Others_mgmt_library3 + 1

	elif packets_library3[i][Dot11].type == 1:
		Control_library3 = Control_library3 + 1
		if packets_library3[i][Dot11].subtype == 10:
			PS_library3 = PS_library3 + 1
		elif packets_library3[i][Dot11].subtype == 11:
			RTS_library3 = RTS_library3 + 1
		elif packets_library3[i][Dot11].subtype == 12:
			CTS_library3 = CTS_library3 + 1
		elif packets_library3[i][Dot11].subtype == 13:
			Acknowledgement_library3 = Acknowledgement_library3 + 1
		elif packets_library3[i][Dot11].subtype == 14:
			CFEnd_library3 = CFEnd_library3 + 1
		elif packets_library3[i][Dot11].subtype == 15:
			CFEnd_Ack_library3 = CFEnd_Ack_library3 + 1
		else:
			Others_ctl_library3 = Others_ctl_library3 + 1
			
	elif packets_library3[i][Dot11].type == 2:
		Data_library3 = Data_library3 + 1
		if packets_library3[i][Dot11].subtype == 0:
			data_library3 = data_library3 + 1
		elif packets_library3[i][Dot11].subtype == 1:
			data_cf_ack_library3 = data_cf_ack_library3 + 1
		elif packets_library3[i][Dot11].subtype == 2:
			data_cf_poll_library3 = data_cf_poll_library3 + 1
		elif packets_library3[i][Dot11].subtype == 3:
			data_cf_ack_cf_poll_library3 = data_cf_ack_cf_poll_library3 + 1
		elif packets_library3[i][Dot11].subtype == 4:
			null_data_library3 = null_data_library3 + 1
		elif packets_library3[i][Dot11].subtype == 5:
			cf_ack_library3 = cf_ack_library3 + 1
		elif packets_library3[i][Dot11].subtype == 6:
			cf_poll_library3 = cf_poll_library3 + 1
		elif packets_library3[i][Dot11].subtype == 7:
			cf_ack_cf_poll_library3 = cf_ack_cf_poll_library3 + 1
		else: 
			Others_data_library3 = Others_data_library3 + 1

			
print("Management Frames: " + str(Management_library3))
print("Control Frames: " + str(Control_library3))
print("Data Frames: " + str(Data_library3)) 
print("----------------------------------")


print("Beacon Frames: " + str(Beacon_library3))
print("Association Request Frames: " +str(AssoReq_library3))
print("Association Response Frames: " +str(AssoResp_library3))
print("Authentication Frames: "+str(Auth_library3))
print("Deauthentication Frames: "+str(Deauth_library3))
print("Dissociation Frames: "+str(Disas_library3))
print("Probe Request Frames: " +str(ProbeReq_library3))
print("Probe Response Frames: " +str(ProbeResp_library3))
print("Reassociation Request Frames: "+str(ReassoReq_library3))
print("Reassociation Response Frames: "+str(ReassoResp_library3))
print("Announcement traffic indication message: "+str(ATIM_library3))
print("Other Management Frames: "+str(Others_mgmt_library3))
print("----------------------------------")


print("Power Save (PS) Poll Frames: " + str(PS_library3))
print("Request to Send (RTS) Frames: " + str(RTS_library3))
print("Clear to Send (CTS) Frames: " + str(CTS_library3))
print("Acknowledgement Frames: " + str(Acknowledgement_library3))
print("Contention Free (CF)- End Frames: " + str(CFEnd_library3))
print("Contention Free (CF)- End + Ack Frames: " + str(CFEnd_Ack_library3))
print("Other Control Frames: "+str(Others_ctl_library3))
print("----------------------------------")

print("Data frames: "+str(data_library3))
print("Data + CF-Acknowledgement frames: "+str(data_cf_ack_library3))
print("Data + CF-Poll frames: "+str(data_cf_poll_library3))
print("Data + CF-Acknowledgement + CF-Poll frames: "+str(data_cf_ack_cf_poll_library3))
print("Null Data frames: "+str(null_data_library3))
print("CF-Acknowledgement (no data) frames: "+str(cf_ack_library3))
print("CF-Poll (no data) frames: "+str(cf_poll_library3))
print("CF-Acknowledgement + CF-Poll (no data) frames: "+str(cf_ack_cf_poll_library3))
print("Other Data Frames: "+str(Others_data_library3))



main_frame_values_library3 = [Data_library3, Control_library3, Management_library3]
main_frame_type_library3 = ['Data Frame','Control Frame','Management Frame']
cols = ['m', 'r','g']
plt.pie(main_frame_values_library3,labels=main_frame_type_library3,colors=cols,autopct='%1.1f%%')
plt.title('Frame Types in Library: Data Set 3')
plt.show()

mgmt_frame_values_library3 = [Beacon_library3, Auth_library3, ProbeReq_library3, ProbeResp_library3, Others_mgmt_library3]
mgmt_frame_type_library3 = ['Beacon Frame','Authentication Frames','Probe Request Frames','Probe Response Frames','Other']
cols = ['b', 'g','r','c','m']
plt.pie(mgmt_frame_values_library3,labels=mgmt_frame_type_library3,colors=cols,autopct='%1.1f%%')
plt.title('Management Frame Types in Library: Data Set 3')
plt.show()

ctl_frame_values_library3 = [CTS_library3, Acknowledgement_library3, Others_ctl_library3]
ctl_frame_type_library3 = ['Clear to Send (CTS) Frames','Acknowledgement Frames','Other']
cols = ['b', 'g','r']
plt.pie(ctl_frame_values_library3,labels=ctl_frame_type_library3,colors=cols,autopct='%1.1f%%')
plt.title('Control Frame Types in Library: Data Set 3')
plt.show()

data_frame_values_library3 = [data_library3, null_data_library3, Others_data_library3]
data_frame_type_library3 = ['Data Frames','Null Data Frames','Other']
cols = ['b', 'g','r']
plt.pie(data_frame_values_library3,labels=data_frame_type_library3,colors=cols,autopct='%1.1f%%')
plt.title('Data Frame Types in Library: Data Set 3')
plt.show()



## Set 4:
### Clyde: 
print("Set 4:")
from scapy.all import *
packets_clyde4 = rdpcap("/home/mawla/Data_522/clyde_1839.cap")
len(packets_clyde4)
print("----------------------------------")
print("Clyde Building Data:")
print("----------------------------------")
print("Total "+ str(len(packets_clyde4)) + " packets were read")
print("----------------------------------")



Data_clyde4 = 0
Control_clyde4 = 0
Management_clyde4 = 0 

Beacon_clyde4 = 0
AssoReq_clyde4 = 0	
AssoResp_clyde4 = 0
Auth_clyde4 = 0
Deauth_clyde4 = 0
Disas_clyde4 = 0
ProbeReq_clyde4 = 0
ProbeResp_clyde4 = 0
ReassoReq_clyde4 = 0
ReassoResp_clyde4 = 0
ATIM_clyde4 = 0
Others_mgmt_clyde4 = 0


PS_clyde4 = 0
RTS_clyde4 = 0
CTS_clyde4 = 0
Acknowledgement_clyde4 = 0
CFEnd_clyde4 = 0
CFEnd_Ack_clyde4 = 0
Others_ctl_clyde4 = 0

data_clyde4 = 0
data_cf_ack_clyde4 = 0
data_cf_poll_clyde4 = 0
data_cf_ack_cf_poll_clyde4 = 0
null_data_clyde4 = 0
cf_ack_clyde4 = 0
cf_poll_clyde4 = 0
cf_ack_cf_poll_clyde4 = 0
Others_data_clyde4 = 0


for i in range(0, len(packets_clyde4)):
	if packets_clyde4[i][Dot11].type == 0:
		Management_clyde4 = Management_clyde4 + 1
		if packets_clyde4[i].haslayer(Dot11Beacon) == 1:
			Beacon_clyde4 = Beacon_clyde4 + 1
		elif packets_clyde4[i].haslayer(Dot11AssoReq) == 1:
			AssoReq_clyde4 = AssoReq_clyde4 + 1
		elif packets_clyde4[i].haslayer(Dot11AssoResp) == 1:
			AssoResp_clyde4 = AssoResp_clyde4 + 1
		elif packets_clyde4[i].haslayer(Dot11Auth) == 1:
			Auth_clyde4 = Auth_clyde4 + 1
		elif packets_clyde4[i].haslayer(Dot11Deauth) == 1:
			Deauth_clyde4 = Deauth_clyde4 + 1
		elif packets_clyde4[i].haslayer(Dot11Disas) == 1:
			Disas_clyde4 = Disas_clyde4 + 1
		elif packets_clyde4[i].haslayer(Dot11ProbeReq) == 1:
			ProbeReq_clyde4 = ProbeReq_clyde4 + 1
		elif packets_clyde4[i].haslayer(Dot11ProbeResp) == 1:
			ProbeResp_clyde4 = ProbeResp_clyde4 + 1
		elif packets_clyde4[i].haslayer(Dot11ReassoReq) == 1:
			ReassoReq_clyde4 = ReassoReq_clyde4 + 1
		elif packets_clyde4[i].haslayer(Dot11ReassoResp) == 1:
			ReassoResp_clyde4= ReassoResp_clyde4 + 1
		elif packets_clyde4[i].haslayer(Dot11ATIM) == 1:
			ATIM_clyde4 = ATIM_clyde4 + 1
		else:
			Others_mgmt_clyde4 = Others_mgmt_clyde4 + 1

	elif packets_clyde4[i][Dot11].type == 1:
		Control_clyde4 = Control_clyde4 + 1
		if packets_clyde4[i][Dot11].subtype == 10:
			PS_clyde4 = PS_clyde4 + 1
		elif packets_clyde4[i][Dot11].subtype == 11:
			RTS_clyde4 = RTS_clyde4 + 1
		elif packets_clyde4[i][Dot11].subtype == 12:
			CTS_clyde4 = CTS_clyde4 + 1
		elif packets_clyde4[i][Dot11].subtype == 13:
			Acknowledgement_clyde4 = Acknowledgement_clyde4 + 1
		elif packets_clyde4[i][Dot11].subtype == 14:
			CFEnd_clyde4 = CFEnd_clyde4 + 1
		elif packets_clyde4[i][Dot11].subtype == 15:
			CFEnd_Ack_clyde4 = CFEnd_Ack_clyde4 + 1
		else:
			Others_ctl_clyde4 = Others_ctl_clyde4 + 1
			
	elif packets_clyde4[i][Dot11].type == 2:
		Data_clyde4 = Data_clyde4 + 1
		if packets_clyde4[i][Dot11].subtype == 0:
			data_clyde4 = data_clyde4 + 1
		elif packets_clyde4[i][Dot11].subtype == 1:
			data_cf_ack_clyde4 = data_cf_ack_clyde4 + 1
		elif packets_clyde4[i][Dot11].subtype == 2:
			data_cf_poll_clyde4 = data_cf_poll_clyde4 + 1
		elif packets_clyde4[i][Dot11].subtype == 3:
			data_cf_ack_cf_poll_clyde4 = data_cf_ack_cf_poll_clyde4 + 1
		elif packets_clyde4[i][Dot11].subtype == 4:
			null_data_clyde4 = null_data_clyde4 + 1
		elif packets_clyde4[i][Dot11].subtype == 5:
			cf_ack_clyde4 = cf_ack_clyde4 + 1
		elif packets_clyde4[i][Dot11].subtype == 6:
			cf_poll_clyde4 = cf_poll_clyde4 + 1
		elif packets_clyde4[i][Dot11].subtype == 7:
			cf_ack_cf_poll_clyde4 = cf_ack_cf_poll_clyde4 + 1
		else: 
			Others_data_clyde4 = Others_data_clyde4 + 1

			
print("Management Frames: " + str(Management_clyde4))
print("Control Frames: " + str(Control_clyde4))
print("Data Frames: " + str(Data_clyde4)) 
print("----------------------------------")


print("Beacon Frames: " + str(Beacon_clyde4))
print("Association Request Frames: " +str(AssoReq_clyde4))
print("Association Response Frames: " +str(AssoResp_clyde4))
print("Authentication Frames: "+str(Auth_clyde4))
print("Deauthentication Frames: "+str(Deauth_clyde4))
print("Dissociation Frames: "+str(Disas_clyde4))
print("Probe Request Frames: " +str(ProbeReq_clyde4))
print("Probe Response Frames: " +str(ProbeResp_clyde4))
print("Reassociation Request Frames: "+str(ReassoReq_clyde4))
print("Reassociation Response Frames: "+str(ReassoResp_clyde4))
print("Announcement traffic indication message: "+str(ATIM_clyde4))
print("Other Management Frames: "+str(Others_mgmt_clyde4))
print("----------------------------------")


print("Power Save (PS) Poll Frames: " + str(PS_clyde4))
print("Request to Send (RTS) Frames: " + str(RTS_clyde4))
print("Clear to Send (CTS) Frames: " + str(CTS_clyde4))
print("Acknowledgement Frames: " + str(Acknowledgement_clyde4))
print("Contention Free (CF)- End Frames: " + str(CFEnd_clyde4))
print("Contention Free (CF)- End + Ack Frames: " + str(CFEnd_Ack_clyde4))
print("Other Control Frames: "+str(Others_ctl_clyde4))
print("----------------------------------")

print("Data frames: "+str(data_clyde4))
print("Data + CF-Acknowledgement frames: "+str(data_cf_ack_clyde4))
print("Data + CF-Poll frames: "+str(data_cf_poll_clyde4))
print("Data + CF-Acknowledgement + CF-Poll frames: "+str(data_cf_ack_cf_poll_clyde4))
print("Null Data frames: "+str(null_data_clyde4))
print("CF-Acknowledgement (no data) frames: "+str(cf_ack_clyde4))
print("CF-Poll (no data) frames: "+str(cf_poll_clyde4))
print("CF-Acknowledgement + CF-Poll (no data) frames: "+str(cf_ack_cf_poll_clyde4))
print("Other Data Frames: "+str(Others_data_clyde4))
print("----------------------------------")



import matplotlib.pyplot as plt
main_frame_values_clyde4 = [Data_clyde4, Control_clyde4, Management_clyde4]
main_frame_type_clyde4 = ['Data Frame','Control Frame','Management Frame']
cols = ['m', 'r','g']
plt.pie(main_frame_values_clyde4,labels=main_frame_type_clyde4,colors=cols,autopct='%1.1f%%')
plt.title('Frame Types in Clyde Building: Data Set 4')
plt.show()

mgmt_frame_values_clyde4 = [Beacon_clyde4, Auth_clyde4, ProbeReq_clyde4, ProbeResp_clyde4, Others_mgmt_clyde4]
mgmt_frame_type_clyde4 = ['Beacon Frame','Authentication Frames','Probe Request Frames','Probe Response Frames','Other']
cols = ['b', 'g','r','c','m']
plt.pie(mgmt_frame_values_clyde4,labels=mgmt_frame_type_clyde4,colors=cols,autopct='%1.1f%%')
plt.title('Management Frame Types in Clyde Building: Data Set 4')
plt.show()

ctl_frame_values_clyde4 = [CTS_clyde4, Acknowledgement_clyde4, Others_ctl_clyde4]
ctl_frame_type_clyde4 = ['Clear to Send (CTS) Frames','Acknowledgement Frames','Other']
cols = ['b', 'g','r']
plt.pie(ctl_frame_values_clyde4,labels=ctl_frame_type_clyde4,colors=cols,autopct='%1.1f%%')
plt.title('Control Frame Types in Clyde Building: Data Set 4')
plt.show()


data_frame_values_clyde4 = [data_clyde4, null_data_clyde4, Others_data_clyde4]
data_frame_type_clyde4 = ['Data Frames','Null Data Frames','Other']
cols = ['b', 'g','r']
plt.pie(data_frame_values_clyde4,labels=data_frame_type_clyde4,colors=cols,autopct='%1.1f%%')
plt.title('Data Frame Types in Clyde Building: Data Set 4')
plt.show()


### Wilk:

from scapy.all import *
packets_wilk4 = rdpcap("/home/mawla/Data_522/wilk_1807.cap")
len(packets_wilk4)
print("----------------------------------")
print("Wilk Student Center Data:")
print("----------------------------------")
print("Total "+ str(len(packets_wilk4)) + " packets were read")
print("----------------------------------")



Data_wilk4 = 0
Control_wilk4 = 0
Management_wilk4 = 0 

Beacon_wilk4 = 0
AssoReq_wilk4 = 0	
AssoResp_wilk4 = 0
Auth_wilk4 = 0
Deauth_wilk4 = 0
Disas_wilk4 = 0
ProbeReq_wilk4 = 0
ProbeResp_wilk4 = 0
ReassoReq_wilk4 = 0
ReassoResp_wilk4 = 0
ATIM_wilk4 = 0
Others_mgmt_wilk4 = 0


PS_wilk4 = 0
RTS_wilk4 = 0
CTS_wilk4 = 0
Acknowledgement_wilk4 = 0
CFEnd_wilk4 = 0
CFEnd_Ack_wilk4 = 0
Others_ctl_wilk4 = 0

data_wilk4 = 0
data_cf_ack_wilk4 = 0
data_cf_poll_wilk4 = 0
data_cf_ack_cf_poll_wilk4 = 0
null_data_wilk4 = 0
cf_ack_wilk4 = 0
cf_poll_wilk4 = 0
cf_ack_cf_poll_wilk4 = 0
Others_data_wilk4 = 0


for i in range(0, len(packets_wilk4)):
	if packets_wilk4[i][Dot11].type == 0:
		Management_wilk4 = Management_wilk4 + 1
		if packets_wilk4[i].haslayer(Dot11Beacon) == 1:
			Beacon_wilk4 = Beacon_wilk4 + 1
		elif packets_wilk4[i].haslayer(Dot11AssoReq) == 1:
			AssoReq_wilk4 = AssoReq_wilk4 + 1
		elif packets_wilk4[i].haslayer(Dot11AssoResp) == 1:
			AssoResp_wilk4 = AssoResp_wilk4 + 1
		elif packets_wilk4[i].haslayer(Dot11Auth) == 1:
			Auth_wilk4 = Auth_wilk4 + 1
		elif packets_wilk4[i].haslayer(Dot11Deauth) == 1:
			Deauth_wilk4 = Deauth_wilk4 + 1
		elif packets_wilk4[i].haslayer(Dot11Disas) == 1:
			Disas_wilk4 = Disas_wilk4 + 1
		elif packets_wilk4[i].haslayer(Dot11ProbeReq) == 1:
			ProbeReq_wilk4 = ProbeReq_wilk4 + 1
		elif packets_wilk4[i].haslayer(Dot11ProbeResp) == 1:
			ProbeResp_wilk4 = ProbeResp_wilk4 + 1
		elif packets_wilk4[i].haslayer(Dot11ReassoReq) == 1:
			ReassoReq_wilk4 = ReassoReq_wilk4 + 1
		elif packets_wilk4[i].haslayer(Dot11ReassoResp) == 1:
			ReassoResp_wilk4= ReassoResp_wilk4 + 1
		elif packets_wilk4[i].haslayer(Dot11ATIM) == 1:
			ATIM_wilk4 = ATIM_wilk4 + 1
		else:
			Others_mgmt_wilk4 = Others_mgmt_wilk4 + 1

	elif packets_wilk4[i][Dot11].type == 1:
		Control_wilk4 = Control_wilk4 + 1
		if packets_wilk4[i][Dot11].subtype == 10:
			PS_wilk4 = PS_wilk4 + 1
		elif packets_wilk4[i][Dot11].subtype == 11:
			RTS_wilk4 = RTS_wilk4 + 1
		elif packets_wilk4[i][Dot11].subtype == 12:
			CTS_wilk4 = CTS_wilk4 + 1
		elif packets_wilk4[i][Dot11].subtype == 13:
			Acknowledgement_wilk4 = Acknowledgement_wilk4 + 1
		elif packets_wilk4[i][Dot11].subtype == 14:
			CFEnd_wilk4 = CFEnd_wilk4 + 1
		elif packets_wilk4[i][Dot11].subtype == 15:
			CFEnd_Ack_wilk4 = CFEnd_Ack_wilk4 + 1
		else:
			Others_ctl_wilk4 = Others_ctl_wilk4 + 1
			
	elif packets_wilk4[i][Dot11].type == 2:
		Data_wilk4 = Data_wilk4 + 1
		if packets_wilk4[i][Dot11].subtype == 0:
			data_wilk4 = data_wilk4 + 1
		elif packets_wilk4[i][Dot11].subtype == 1:
			data_cf_ack_wilk4 = data_cf_ack_wilk4 + 1
		elif packets_wilk4[i][Dot11].subtype == 2:
			data_cf_poll_wilk4 = data_cf_poll_wilk4 + 1
		elif packets_wilk4[i][Dot11].subtype == 3:
			data_cf_ack_cf_poll_wilk4 = data_cf_ack_cf_poll_wilk4 + 1
		elif packets_wilk4[i][Dot11].subtype == 4:
			null_data_wilk4 = null_data_wilk4 + 1
		elif packets_wilk4[i][Dot11].subtype == 5:
			cf_ack_wilk4 = cf_ack_wilk4 + 1
		elif packets_wilk4[i][Dot11].subtype == 6:
			cf_poll_wilk4 = cf_poll_wilk4 + 1
		elif packets_wilk4[i][Dot11].subtype == 7:
			cf_ack_cf_poll_wilk4 = cf_ack_cf_poll_wilk4 + 1
		else: 
			Others_data_wilk4 = Others_data_wilk4 + 1

			
print("Management Frames: " + str(Management_wilk4))
print("Control Frames: " + str(Control_wilk4))
print("Data Frames: " + str(Data_wilk4)) 
print("----------------------------------")


print("Beacon Frames: " + str(Beacon_wilk4))
print("Association Request Frames: " +str(AssoReq_wilk4))
print("Association Response Frames: " +str(AssoResp_wilk4))
print("Authentication Frames: "+str(Auth_wilk4))
print("Deauthentication Frames: "+str(Deauth_wilk4))
print("Dissociation Frames: "+str(Disas_wilk4))
print("Probe Request Frames: " +str(ProbeReq_wilk4))
print("Probe Response Frames: " +str(ProbeResp_wilk4))
print("Reassociation Request Frames: "+str(ReassoReq_wilk4))
print("Reassociation Response Frames: "+str(ReassoResp_wilk4))
print("Announcement traffic indication message: "+str(ATIM_wilk4))
print("Other Management Frames: "+str(Others_mgmt_wilk4))
print("----------------------------------")


print("Power Save (PS) Poll Frames: " + str(PS_wilk4))
print("Request to Send (RTS) Frames: " + str(RTS_wilk4))
print("Clear to Send (CTS) Frames: " + str(CTS_wilk4))
print("Acknowledgement Frames: " + str(Acknowledgement_wilk4))
print("Contention Free (CF)- End Frames: " + str(CFEnd_wilk4))
print("Contention Free (CF)- End + Ack Frames: " + str(CFEnd_Ack_wilk4))
print("Other Control Frames: "+str(Others_ctl_wilk4))
print("----------------------------------")

print("Data frames: "+str(data_wilk4))
print("Data + CF-Acknowledgement frames: "+str(data_cf_ack_wilk4))
print("Data + CF-Poll frames: "+str(data_cf_poll_wilk4))
print("Data + CF-Acknowledgement + CF-Poll frames: "+str(data_cf_ack_cf_poll_wilk4))
print("Null Data frames: "+str(null_data_wilk4))
print("CF-Acknowledgement (no data) frames: "+str(cf_ack_wilk4))
print("CF-Poll (no data) frames: "+str(cf_poll_wilk4))
print("CF-Acknowledgement + CF-Poll (no data) frames: "+str(cf_ack_cf_poll_wilk4))
print("Other Data Frames: "+str(Others_data_wilk4))

main_frame_values_wilk4 = [Data_wilk4, Control_wilk4, Management_wilk4]
main_frame_type_wilk4 = ['Data Frame','Control Frame','Management Frame']
cols = ['m', 'r','g']
plt.pie(main_frame_values_wilk4,labels=main_frame_type_wilk4,colors=cols,autopct='%1.1f%%')
plt.title('Frame Types in Wilk Student Center: Data Set 4')
plt.show()


mgmt_frame_values_wilk4 = [Beacon_wilk4, Auth_wilk4, ProbeReq_wilk4, ProbeResp_wilk4, Others_mgmt_wilk4]
mgmt_frame_type_wilk4 = ['Beacon Frame','Authentication Frames','Probe Request Frames','Probe Response Frames','Other']
cols = ['b', 'g','r','c','m']
plt.pie(mgmt_frame_values_wilk4,labels=mgmt_frame_type_wilk4,colors=cols,autopct='%1.1f%%')
plt.title('Management Frame Types in Wilk Student Center Building: Data Set 4')
plt.show()

ctl_frame_values_wilk4 = [CTS_wilk4, Acknowledgement_wilk4, Others_ctl_wilk4]
ctl_frame_type_wilk4 = ['Clear to Send (CTS) Frames','Acknowledgement Frames','Other']
cols = ['b', 'g','r']
plt.pie(ctl_frame_values_wilk4,labels=ctl_frame_type_wilk4,colors=cols,autopct='%1.1f%%')
plt.title('Control Frame Types in Wilk Student Center: Data Set 4')
plt.show()

data_frame_values_wilk4 = [data_wilk4, null_data_wilk4, Others_data_wilk4]
data_frame_type_wilk4 = ['Data Frames','Null Data Frames','Other']
cols = ['b', 'g','r']
plt.pie(data_frame_values_wilk4,labels=data_frame_type_wilk4,colors=cols,autopct='%1.1f%%')
plt.title('Data Frame Types in Wilk Student Center: Data Set 4')
plt.show()


### library: 

from scapy.all import *
packets_library4 = rdpcap("/home/mawla/Data_522/library_1817.cap")
len(packets_library4)
print("----------------------------------")
print("Library Data:")
print("----------------------------------")
print("Total "+ str(len(packets_library4)) + " packets were read")
print("----------------------------------")



Data_library4 = 0
Control_library4 = 0
Management_library4 = 0 

Beacon_library4 = 0
AssoReq_library4 = 0	
AssoResp_library4 = 0
Auth_library4 = 0
Deauth_library4 = 0
Disas_library4 = 0
ProbeReq_library4 = 0
ProbeResp_library4 = 0
ReassoReq_library4 = 0
ReassoResp_library4 = 0
ATIM_library4 = 0
Others_mgmt_library4 = 0


PS_library4 = 0
RTS_library4 = 0
CTS_library4 = 0
Acknowledgement_library4 = 0
CFEnd_library4 = 0
CFEnd_Ack_library4 = 0
Others_ctl_library4 = 0

data_library4 = 0
data_cf_ack_library4 = 0
data_cf_poll_library4 = 0
data_cf_ack_cf_poll_library4 = 0
null_data_library4 = 0
cf_ack_library4 = 0
cf_poll_library4 = 0
cf_ack_cf_poll_library4 = 0
Others_data_library4 = 0


for i in range(0, len(packets_library4)):
	if packets_library4[i][Dot11].type == 0:
		Management_library4 = Management_library4 + 1
		if packets_library4[i].haslayer(Dot11Beacon) == 1:
			Beacon_library4 = Beacon_library4 + 1
		elif packets_library4[i].haslayer(Dot11AssoReq) == 1:
			AssoReq_library4 = AssoReq_library4 + 1
		elif packets_library4[i].haslayer(Dot11AssoResp) == 1:
			AssoResp_library4 = AssoResp_library4 + 1
		elif packets_library4[i].haslayer(Dot11Auth) == 1:
			Auth_library4 = Auth_library4 + 1
		elif packets_library4[i].haslayer(Dot11Deauth) == 1:
			Deauth_library4 = Deauth_library4 + 1
		elif packets_library4[i].haslayer(Dot11Disas) == 1:
			Disas_library4 = Disas_library4 + 1
		elif packets_library4[i].haslayer(Dot11ProbeReq) == 1:
			ProbeReq_library4 = ProbeReq_library4 + 1
		elif packets_library4[i].haslayer(Dot11ProbeResp) == 1:
			ProbeResp_library4 = ProbeResp_library4 + 1
		elif packets_library4[i].haslayer(Dot11ReassoReq) == 1:
			ReassoReq_library4 = ReassoReq_library4 + 1
		elif packets_library4[i].haslayer(Dot11ReassoResp) == 1:
			ReassoResp_library4= ReassoResp_library4 + 1
		elif packets_library4[i].haslayer(Dot11ATIM) == 1:
			ATIM_library4 = ATIM_library4 + 1
		else:
			Others_mgmt_library4 = Others_mgmt_library4 + 1

	elif packets_library4[i][Dot11].type == 1:
		Control_library4 = Control_library4 + 1
		if packets_library4[i][Dot11].subtype == 10:
			PS_library4 = PS_library4 + 1
		elif packets_library4[i][Dot11].subtype == 11:
			RTS_library4 = RTS_library4 + 1
		elif packets_library4[i][Dot11].subtype == 12:
			CTS_library4 = CTS_library4 + 1
		elif packets_library4[i][Dot11].subtype == 13:
			Acknowledgement_library4 = Acknowledgement_library4 + 1
		elif packets_library4[i][Dot11].subtype == 14:
			CFEnd_library4 = CFEnd_library4 + 1
		elif packets_library4[i][Dot11].subtype == 15:
			CFEnd_Ack_library4 = CFEnd_Ack_library4 + 1
		else:
			Others_ctl_library4 = Others_ctl_library4 + 1
			
	elif packets_library4[i][Dot11].type == 2:
		Data_library4 = Data_library4 + 1
		if packets_library4[i][Dot11].subtype == 0:
			data_library4 = data_library4 + 1
		elif packets_library4[i][Dot11].subtype == 1:
			data_cf_ack_library4 = data_cf_ack_library4 + 1
		elif packets_library4[i][Dot11].subtype == 2:
			data_cf_poll_library4 = data_cf_poll_library4 + 1
		elif packets_library4[i][Dot11].subtype == 3:
			data_cf_ack_cf_poll_library4 = data_cf_ack_cf_poll_library4 + 1
		elif packets_library4[i][Dot11].subtype == 4:
			null_data_library4 = null_data_library4 + 1
		elif packets_library4[i][Dot11].subtype == 5:
			cf_ack_library4 = cf_ack_library4 + 1
		elif packets_library4[i][Dot11].subtype == 6:
			cf_poll_library4 = cf_poll_library4 + 1
		elif packets_library4[i][Dot11].subtype == 7:
			cf_ack_cf_poll_library4 = cf_ack_cf_poll_library4 + 1
		else: 
			Others_data_library4 = Others_data_library4 + 1

			
print("Management Frames: " + str(Management_library4))
print("Control Frames: " + str(Control_library4))
print("Data Frames: " + str(Data_library4)) 
print("----------------------------------")


print("Beacon Frames: " + str(Beacon_library4))
print("Association Request Frames: " +str(AssoReq_library4))
print("Association Response Frames: " +str(AssoResp_library4))
print("Authentication Frames: "+str(Auth_library4))
print("Deauthentication Frames: "+str(Deauth_library4))
print("Dissociation Frames: "+str(Disas_library4))
print("Probe Request Frames: " +str(ProbeReq_library4))
print("Probe Response Frames: " +str(ProbeResp_library4))
print("Reassociation Request Frames: "+str(ReassoReq_library4))
print("Reassociation Response Frames: "+str(ReassoResp_library4))
print("Announcement traffic indication message: "+str(ATIM_library4))
print("Other Management Frames: "+str(Others_mgmt_library4))
print("----------------------------------")


print("Power Save (PS) Poll Frames: " + str(PS_library4))
print("Request to Send (RTS) Frames: " + str(RTS_library4))
print("Clear to Send (CTS) Frames: " + str(CTS_library4))
print("Acknowledgement Frames: " + str(Acknowledgement_library4))
print("Contention Free (CF)- End Frames: " + str(CFEnd_library4))
print("Contention Free (CF)- End + Ack Frames: " + str(CFEnd_Ack_library4))
print("Other Control Frames: "+str(Others_ctl_library4))
print("----------------------------------")

print("Data frames: "+str(data_library4))
print("Data + CF-Acknowledgement frames: "+str(data_cf_ack_library4))
print("Data + CF-Poll frames: "+str(data_cf_poll_library4))
print("Data + CF-Acknowledgement + CF-Poll frames: "+str(data_cf_ack_cf_poll_library4))
print("Null Data frames: "+str(null_data_library4))
print("CF-Acknowledgement (no data) frames: "+str(cf_ack_library4))
print("CF-Poll (no data) frames: "+str(cf_poll_library4))
print("CF-Acknowledgement + CF-Poll (no data) frames: "+str(cf_ack_cf_poll_library4))
print("Other Data Frames: "+str(Others_data_library4))



main_frame_values_library4 = [Data_library4, Control_library4, Management_library4]
main_frame_type_library4 = ['Data Frame','Control Frame','Management Frame']
cols = ['m', 'r','g']
plt.pie(main_frame_values_library4,labels=main_frame_type_library4,colors=cols,autopct='%1.1f%%')
plt.title('Frame Types in Library: Data Set 4')
plt.show()

mgmt_frame_values_library4 = [Beacon_library4, Auth_library4, ProbeReq_library4, ProbeResp_library4, Others_mgmt_library4]
mgmt_frame_type_library4 = ['Beacon Frame','Authentication Frames','Probe Request Frames','Probe Response Frames','Other']
cols = ['b', 'g','r','c','m']
plt.pie(mgmt_frame_values_library4,labels=mgmt_frame_type_library4,colors=cols,autopct='%1.1f%%')
plt.title('Management Frame Types in Library: Data Set 4')
plt.show()

ctl_frame_values_library4 = [CTS_library4, Acknowledgement_library4, Others_ctl_library4]
ctl_frame_type_library4 = ['Clear to Send (CTS) Frames','Acknowledgement Frames','Other']
cols = ['b', 'g','r']
plt.pie(ctl_frame_values_library4,labels=ctl_frame_type_library4,colors=cols,autopct='%1.1f%%')
plt.title('Control Frame Types in Library: Data Set 4')
plt.show()

data_frame_values_library4 = [data_library4, null_data_library4, Others_data_library4]
data_frame_type_library4 = ['Data Frames','Null Data Frames','Other']
cols = ['b', 'g','r']
plt.pie(data_frame_values_library4,labels=data_frame_type_library4,colors=cols,autopct='%1.1f%%')
plt.title('Data Frame Types in Library: Data Set 4')
plt.show()





















