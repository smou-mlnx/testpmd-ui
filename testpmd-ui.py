#!/usr/bin/python3

from scapy.all import *
from flexx import flx, app

class DeviceBox(flx.PyWidget):

	def init(self):
		self.box=[]
		with flx.VBox():
			flx.Label(text='-------- Device List --------', )
			for i, dev in enumerate(self.root.interface_list):
				txt=" PCI_ID: " + self.root.pci_list[i] + " mac: " + self.root.mac_list[i].upper() + "Interface: " + dev 
				self.box.append(flx.CheckBox(text=txt))

	@flx.reaction
	def a_button_was_pressed(self):
		self.root.dev_arg.clear()
		for j, checkbox in enumerate(self.box):
			if checkbox.checked:
				self.root.dev_arg.append(self.root.pci_list[j])
				print(self.root.pci_list[j])

class EALBox(flx.PyWidget):

	def init(self):
		self.box=[]
		with flx.VBox():
			flx.Label(text='-------- Device List --------', )
			for i, dev in enumerate(self.root.interface_list):
				txt=" PCI_ID: " + self.root.pci_list[i] + " mac: " + self.root.mac_list[i].upper() + "Interface: " + dev 
				self.box.append(flx.CheckBox(text=txt))

	@flx.reaction
	def a_button_was_pressed(self):
		self.root.dev_arg.clear()
		for j, checkbox in enumerate(self.box):
			if checkbox.checked:
				self.root.dev_arg.append(self.root.pci_list[j])
				print(self.root.pci_list[j])


class TestpmdUI(flx.PyWidget):

	def get_dev_info(self):
		pci_l = subprocess.check_output("lspci -D | grep Mellanox | awk '{print $1}'", shell=True)
		pci_l = pci_l.decode()
		pci_l = pci_l.split('\n')
		del(pci_l[-1])
		for dev in pci_l:
			self.pci_list.append(''.join(dev))
			dev_path="/sys/bus/pci/devices/" + dev + "/net"
			self.interface_list.append(' '.join(os.listdir(dev_path)))
			net_path="/sys/class/net/"+ self.interface_list[-1] + "/address"
			self.mac_list.append(open(net_path).read())

	def init(self):
		self.pci_list=[]
		self.interface_list=[]
		self.mac_list=[]
		self.dev_arg=[]
		self.get_dev_info()
		with flx.VBox(flex=1):
			self.db=DeviceBox()

              
if __name__ == '__main__':
	if sys.argv[-1] in ["--help","-h"]:
		print("""
		Start Testpmd web GUI in server mode.
		Please open URL in broswer Chrome or Firefox
        
		Options:
			--flexx-hostname=<host> Host/IP to listen on
			--flexx-port=<port>     Port number to listen on
			--app:                  Start as application single user mode, quit once page close.
			--help(-h)              Show this help
		""")
	elif sys.argv[-1] == "--app":
		flx.launch(TestpmdUI)
		flx.run()
	else:
		app.serve(TestpmdUI)
		app.start()
