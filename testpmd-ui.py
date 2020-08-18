#!/usr/bin/python3

from scapy.all import *
from flexx import flx, app, ui, event

class DeviceBox(flx.PyWidget):

	def init(self):
		self.box=[]
		with flx.VBox():
			flx.Label(text='-------- Device List --------', flex=1, css_class="center")
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
			flx.Label(text='-------- EAL  args --------', flex=1, css_class="center")
			with flx.HBox():
				ui.Label(text='--master-core:', flex=3)
				self.mc = ui.LineEdit(text='0', flex=2)
				ui.Label(text='-c COREMASK:', flex=3)
				self.cm = ui.LineEdit(text='0xffff', flex=2)

	def get_eal_arg(self):
		eal_arg = "--master-core="+self.mc.text + " -c " + self.cm.text
		return eal_arg

class APPBox(flx.PyWidget):

	def init(self):
		self.box=[]
		with flx.VBox():
			flx.Label(text='-------- Testpmd args --------', flex=1, css_class="center")
			with flx.HBox():
				self.cb_as = flx.CheckBox(text="Auto-start")
				self.cb_crc = flx.CheckBox(text="disable-crc-strip")
				self.cb_fia = flx.CheckBox(text="flow-isolate-all")
			with flx.HBox():
				ui.Label(text='--rxq:')
				self.rxq = ui.LineEdit(text='1')
				ui.Label(text='--rxd:')
				self.rxd = ui.LineEdit(text='64')
				ui.Label(text='--txq:')
				self.txq = ui.LineEdit(text='1')
				ui.Label(text='--txd:')
				self.txd = ui.LineEdit(text='64')
				ui.Label(text='--hairpin:')
				self.hairpin = ui.LineEdit(text='1')


	def get_testpmd_arg(self):
		testpmd_arg = "--rxq="+self.rxq.text + " --txq=" + self.txq.text
		return testpmd_arg

class ItemBox(flx.PyWidget):

	def init(self):
		self.pattern = "pattern "
		with flx.VBox():
			with flx.HBox():
				ui.Label(text='pattern:')
				self.item = ui.ComboBox(editable=True, selected_key='eth', options=('eth', 'ipv4', 'ipv6', 'tcp', 'udp', 'vlan', 'vxlan', 'tag'))
				self.al = ui.Label(text='src:')
				self.av = ui.LineEdit(text='1')
				self.am = ui.Label(text='src_mask:')
				self.amv = ui.LineEdit(text='1')
				self.bl = ui.Label(text='dst:')
				self.bv = ui.LineEdit(text='1')
				self.bm = ui.Label(text='dst_mask:')
				self.bmv = ui.LineEdit(text='1')
				self.add = flx.Button(text='add')
				self.cl = flx.Button(text='clear')
			with flx.HBox():
				self.showitem = ui.Label(text="No pattern")

	def get_item(self):
		return self.pattern + " end"

	@flx.reaction('add.pointer_click')
	def add_widget(self, *events):
		self.pattern = self.pattern + self.item.selected_key + "/"
		ttext = self.pattern + "end"
		self.showitem.set_text(ttext)

	@flx.reaction('cl.pointer_click')
	def cl_widget(self, *events):
		self.pattern = "pattern "
		self.showitem.set_text("No pattern")

	@event.reaction
	def combo_key_change(self):
		if self.item.selected_index < 3:
			self.al.set_text("src:")
			self.av.set_text('1')
			self.am.set_text("src_mask:")
			self.amv.set_text('1')
			self.bl.set_text("dst:")
			self.bv.set_text('1')
			self.bm.set_text("dst_mask:")
			self.bmv.set_text('1')
		elif self.item.selected_index < 5:
			self.al.set_text("src_port:")
			self.av.set_text('1')
			self.am.set_text("dst_port:")
			self.amv.set_text('1')
			self.bl.set_text("")
			self.bv.set_text('')
			self.bm.set_text("")
			self.bmv.set_text('')
		elif self.item.selected_index is 5:
			self.al.set_text("vlan_id")
			self.av.set_text('56')
			self.am.set_text("")
			self.amv.set_text('')
			self.bl.set_text("")
			self.bv.set_text('')
			self.bm.set_text("")
			self.bmv.set_text('')
		elif self.item.selected_index is 6:
			self.al.set_text("vxlan_id")
			self.av.set_text('56')
			self.am.set_text("")
			self.amv.set_text('')
			self.bl.set_text("")
			self.bv.set_text('')
			self.bm.set_text("")
			self.bmv.set_text('')
		elif self.item.selected_index is 7:
			self.al.set_text("tg_id")
			self.av.set_text('56')
			self.am.set_text("")
			self.amv.set_text('')
			self.bl.set_text("")
			self.bv.set_text('')
			self.bm.set_text("")
			self.bmv.set_text('')



class FlowBox(flx.PyWidget):

	def init(self):
		self.box=[]
		with flx.VBox():
			flx.Label(text='-------- Add flow --------', flex=1, css_class="center")
			with flx.HBox():
				ui.Label(text='attr:')
				ui.Label(text='port_id:')
				self.port_id = ui.LineEdit(text='0')
				ui.Label(text='group:')
				self.port_id = ui.LineEdit(text='1')
				self.attr = ui.ComboBox(editable=True, selected_key='ingress', options=('ingress', 'egress', 'transfer'))
			self.item = ItemBox()

	def get_testpmd_arg(self):
		testpmd_arg = "--rxq="+self.rxq.text + " --txq=" + self.txq.text
		return testpmd_arg

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
			self.eb=EALBox()
			self.ab=APPBox()
			self.fb=FlowBox()

              
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
