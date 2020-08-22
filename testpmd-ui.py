#!/usr/bin/python3

from scapy.all import *
from flexx import flx, app, ui, event
import shlex, subprocess
import threading
import time
import pexpect, asyncio

class TestPMD(flx.Component):
	def init(self):
		self.logfile = io.StringIO()
		self.shell = None
		self.sent_lines = 0
		self.total_lines = 0
		self.alive = False
		self.refresh()

	def prompt(self):
		idx = self.shell.expect(['testpmd>', pexpect.EOF, pexpect.TIMEOUT])
		if idx:
			self.alive = False
			self.shell.close()
			return
		while self.alive and self.shell.buffer and self.shell.buffer.strip():
			idx = self.shell.expect(['testpmd>', pexpect.EOF, pexpect.TIMEOUT])
			if idx:
				self.alive = False
				self.shell.close()
				return
		self.alive = True

	def start(self, cmd):
		if not self.alive:
			self.shell = pexpect.spawn(cmd, echo=False, encoding='utf-8')
			self.shell.logfile = self.logfile
			self.prompt()

	def input(self, data):
		self.shell.sendline(data)
		self.prompt()

	def output(self):
		if self.shell:
			lines = self.logfile.getvalue().splitlines()
			self.total_lines = len(lines)
		if self.sent_lines < self.total_lines:
			self.emit('output', dict(buffer=lines[self.sent_lines:]))
			self.sent_lines = self.total_lines

	def refresh(self):
		self.output()
		asyncio.get_event_loop().call_later(1, self.refresh)

testpmd = TestPMD()

class TestPMDOut(flx.Label):

    CSS = """
    .flx-TestPMDOut {
        overflow-y:scroll;
        background: black;
		color: lightgreen;
        border: 1px solid #444;
        margin: 3px;
		font-family: Consolas, Courier, monospace;
		font-size: 0.875em;
    }
    """

    def init(self):
        super().init()
        global window
        self._se = window.document.createElement('div')

    def sanitize(self, text):
        self._se.textContent = text
        text = self._se.innerHTML
        self._se.textContent = ''
        return text

    @flx.action
    def add_line(self, msg):
        line = self.sanitize(msg)
        self.set_html(self.html + line + '<br />')
        div = RawJS('document.getElementsByClassName("flx-TestPMDOut")[0]')
        div.scrollTop = div.scrollHeight

class DeviceBox(flx.PyWidget):

	def init(self):
		self.box=[]
		with flx.HSplit(flex=1,style='border:2px solid gray;border-radius: 5px'):
			with flx.VBox(flex=1):
				flx.Label(text=' ', flex=1)
				flx.Label(text='Device List', flex=1)
				flx.Label(text=' ', flex=1)
			with flx.VBox(flex=3):
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
		with flx.VBox(flex=1, title = 'EAL args', style='border:2px solid gray;border-radius: 5px'):
			with flx.HBox():
				ui.Label(flex=1,text='EAL args:  ')
				ui.Label(flex=0,text='--master-lcore:')
				self.mc = ui.LineEdit(flex=2,text='0')
				ui.Label(flex=1,text='')
				ui.Label(flex=0, text="    -c COREMASK:")
				self.cm = ui.LineEdit(flex=2,text='0xff')
				ui.Label(flex=1,text='')
				ui.Label(flex=0, text='    --file-prefix:')
				self.fp = ui.LineEdit(flex=2,text='/tmp/')
				self.nohp = flx.CheckBox(flex=2,text='--no-huge')
				self.hpunlink = flx.CheckBox(flex=2,text='--huge-unlink')

	def get_eal_arg(self):
		eal_arg = "--master-lcore="+self.mc.text + " -c " + self.cm.text
		return eal_arg



class APPBox(flx.PyWidget):

	def init(self):
		self.box=[]
		with flx.VBox(flex=1,  style='border:2px solid gray;border-radius: 5px;text-align:left'):
			with flx.HFix(flex=1, style='text-align:left'):
				flx.Label(text='Testpmd args:')
				self.cb_as = flx.CheckBox(text="auto-start")
				self.cb_crc = flx.CheckBox(text="disable-crc-strip")
				self.cb_fia = flx.CheckBox(text="flow-isolate-all")
			with flx.HBox(flex=1):
				ui.Label(text='--rxq:', flex=0)
				self.rxq = ui.LineEdit(text='1', flex=1)
				ui.Label(flex=1,text='')
				ui.Label(text='--rxd:', flex=0)
				self.rxd = ui.LineEdit(text='64', flex=1)
				ui.Label(flex=1,text='')
				ui.Label(text='--txq:', flex=0)
				self.txq = ui.LineEdit(text='1', flex=1)
				ui.Label(flex=1,text='')
				ui.Label(text='--txd:',flex=0)
				self.txd = ui.LineEdit(text='64', flex=1)
				ui.Label(flex=1,text='')
				ui.Label(text='--hairpin:', flex=0)
				self.hairpin = ui.LineEdit(text='0', flex=1)
			with flx.HFix(flex=1, style=' text-align:left'):
				self.cmdline = ui.Label(text='testpmd cmdline:', flex=10)
				self.start = flx.Button(text='start', flex=1)

	def get_testpmd_arg(self):
		testpmd_arg = "--rxq="+self.rxq.text + " --txq=" + self.txq.text + " --rxd=" + self.rxd.text + " --txd=" + self.txd.text
		if self.hairpin.text != "0":
			testpmd_arg += " --hairpin " + self.hairpin.text
		if self.cb_crc.checked:
			testpmd_arg += " --disable-crc-strip "
		if self.cb_fia.checked:
			testpmd_arg += " --flow-isolate-all "
		if self.cb_as.checked:
			testpmd_arg += " -a "
		return testpmd_arg


	@flx.reaction('start.pointer_click')
	def add_widget(self, *events):
		if len(self.root.dev_arg) == 0:
			self.cmdline.set_text("Device not selected")
			return
		dev_list = ""
		for pcid in self.root.dev_arg:
			dev_list += " -w " + ''.join(pcid) + " "
		testpmd_cmdline = "sudo /root/test/dpdk.org/x86_64-native-linuxapp-gcc/app/testpmd " + self.root.eb.get_eal_arg() + dev_list + " -- " +self.get_testpmd_arg() + " -i"
		self.cmdline.set_text(testpmd_cmdline)
		testpmd.start(testpmd_cmdline)

class ItemBox(flx.PyWidget):

	def init(self):
		self.pattern = "pattern "
		with flx.VBox(flex=1, style='border:2px solid gray;border-radius: 5px'):
			with flx.HBox(flex=0):
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
		return self.pattern + " end "

	@flx.reaction('add.pointer_click')
	def add_widget(self, *events):
		ttext = self.pattern + self.item.selected_key
		if self.item.selected_index < 3:
			if self.av.text != '0':
				ttext += " src is " + self.av.text
			if self.amv.text != '0':
				ttext += " src mask " + self.amv.text
			if self.bv.text != '0':
				ttext += " dst is " + self.bv.text
			if self.bmv.text != '0':
				ttext += " dst mask " + self.bmv.text
		elif self.item.selected_index < 5:
			if self.av.text != '-1':
				ttext += " src is " + self.av.text
			if self.amv.text != '-1':
				ttext += " dst is " + self.amv.text
		elif self.item.selected_index is 5:
			if self.av.text != '0':
				ttext += " vid is " + self.av.text
		elif self.item.selected_index is 6:
			if self.av.text != '0':
				ttext += " vni is " + self.av.text
		elif self.item.selected_index is 7:
			if self.av.text != '0':
				ttext += " data is " + self.av.text

		ttext += " / "
		self.pattern = ttext
		self.showitem.set_text(ttext + " end")

	@flx.reaction('cl.pointer_click')
	def cl_widget(self, *events):
		self.pattern = "pattern "
		self.showitem.set_text("No pattern")

	@event.reaction
	def combo_key_change(self):
		if self.item.selected_index < 3:
			self.al.set_text("src:")
			self.av.set_text('0')
			self.am.set_text("src_mask:")
			self.amv.set_text('0')
			self.bl.set_text("dst:")
			self.bv.set_text('0')
			self.bm.set_text("dst_mask:")
			self.bmv.set_text('0')
		elif self.item.selected_index < 5:
			self.al.set_text("src_port:")
			self.av.set_text('-1')
			self.am.set_text("dst_port:")
			self.amv.set_text('-1')
			self.bl.set_text("")
			self.bv.set_text('')
			self.bm.set_text("")
			self.bmv.set_text('')
		elif self.item.selected_index is 5:
			self.al.set_text("vlan_id")
			self.av.set_text('0')
			self.am.set_text("")
			self.amv.set_text('')
			self.bl.set_text("")
			self.bv.set_text('')
			self.bm.set_text("")
			self.bmv.set_text('')
		elif self.item.selected_index is 6:
			self.al.set_text("vxlan_id")
			self.av.set_text('0')
			self.am.set_text("")
			self.amv.set_text('')
			self.bl.set_text("")
			self.bv.set_text('')
			self.bm.set_text("")
			self.bmv.set_text('')
		elif self.item.selected_index is 7:
			self.al.set_text("tag_id")
			self.av.set_text('0')
			self.am.set_text("")
			self.amv.set_text('')
			self.bl.set_text("")
			self.bv.set_text('')
			self.bm.set_text("")
			self.bmv.set_text('')

class ActionBox(flx.PyWidget):

	def init(self):
		with flx.VBox(style='border:2px solid gray;border-radius: 5px; align:left'):
			with flx.VBox(style='border:2px solid gray;border-radius: 5px'):
				with flx.HSplit(flex=1, style='text-align:left;'):
					ui.Label(text='vxlan encap data:')
					ui.Label(text='eth src:')
					self.eth_src = ui.LineEdit(text='0')
					ui.Label(text='eth dst:')
					self.eth_dst = ui.LineEdit(text='0')
					ui.Label(text='eth type:')
					self.eth_type = ui.LineEdit(text='0x0800')
					ui.Label(text='ip src:')
					self.ip_src = ui.LineEdit(text='0')
					ui.Label(text='ip dst:')
					self.ip_dst = ui.LineEdit(text='0')
					ui.Label(text='udp src:')
					self.udp_src = ui.LineEdit(text='0')
					ui.Label(text='udp dst:')
					self.udp_dst = ui.LineEdit(text='4789')
					ui.Label(text='vni:')
					self.vni = ui.LineEdit(text='123')
				with flx.HBox():
					self.encap_disp = ui.Label(text='encap_data:')
			with flx.HSplit():
				self.smacs = flx.CheckBox(text="set_mac_src", flex=2)
				self.smacs_v = ui.LineEdit(text='192.168.1.2', flex=2)
				self.smacd = flx.CheckBox(text="set_mac_dst", flex=2)
				self.smacd_v = ui.LineEdit(text='192.168.1.5', flex=2)
				self.sip4s = flx.CheckBox(text="set_ipv4_src", flex=2)
				self.sip4s_v = ui.LineEdit(text='192.168.1.2', flex=2)
				self.sip4d = flx.CheckBox(text="set_ipv4_dst",flex=2)
				self.sip4d_v = ui.LineEdit(text='192.168.1.5',flex=2)
				self.stps = flx.CheckBox(text="set_tp_src",flex=2)
				self.stps_v = ui.LineEdit(text='3456', flex=1)
				self.stpd = flx.CheckBox(text="set_tp_dst", flex=2)
				self.stpd_v = ui.LineEdit(text='3446', flex=1)
			with flx.HBox():
				self.cnt = flx.CheckBox(text="count")
				self.decap = flx.CheckBox(text="vxlan_decap")
				self.encap = flx.CheckBox(text="vxlan_encap")

				self.stag = flx.CheckBox(text="set_tag")
				self.stag_v = ui.LineEdit(text='12')

				self.fate = ui.ComboBox(editable=True, selected_key='jump', options=('jump', 'drop', 'rss', 'queue', 'port id'))
				self.fate_v = ui.LineEdit(text='2')
				self.add = flx.Button(text='add')
			with flx.HBox():
				self.flow_detail = ui.Label(text="Flow to be added")

	@flx.reaction('add.pointer_click')
	def add_actions(self, *events):
		print(self.root.fb.item.get_item())
		if self.root.fb.item.get_item() == "pattern  end ":
			self.flow_detail.set_text("Pattern not selected")
			return

		self.encap_v = "set vxlan ip-version ipv4 vni " + self.vni.text + " udp-src " + self.udp_src.text + " udp-dst " + self.udp_dst.text + " ip-src " + self.ip_src.text + " ip-dst " +\
				self.ip_dst.text + " eth-src " + self.eth_src.text + " eth-dst " + self.eth_dst.text
		self.encap_disp.set_text(self.encap_v)
		self.action = " actions "
		if (self.stag.checked):
			self.action += " set_tag data " + self.stag_v.text + " / "
		if (self.smacs.checked):
			self.action += " set_mac_src mac_addr " + self.smacs_v.text + " / "
		if (self.smacd.checked):
			self.action += " set_mac_dst mac_addr " + self.smacd_v.text + " / "
		if (self.sip4s.checked):
			self.action += " set_ipv4_src ipv4_addr " + self.sip4s_v.text + " / "
		if (self.sip4d.checked):
			self.action += " set_ipv4_dst ipv4_addr " + self.sip4d_v.text + " / "
		if (self.stpd.checked):
			self.action += " set_tp_dst port " + self.stpd_v.text + " / "
		if (self.stps.checked):
			self.action += " set_tp_src port " + self.stps_v.text + " / "

		if (self.cnt.checked):
			self.action += " count / "
		if (self.decap.checked):
			self.action += " vxlan_decap / "
		if (self.encap.checked):
			self.action += " vxlan_encap / "

		if (self.fate.selected_key == "jump"):
			self.action += " jump group " + self.fate_v.text + " / "
		elif (self.fate.selected_key == "port_id"):
			self.action += " port_id id " + self.fate_v.text + " / "
		elif (self.fate.selected_key == "queue"):
			self.action += " queue index " + self.fate_v.text + " / "
		elif (self.fate.selected_key == "rss"):
			self.action += " rss / "
		elif (self.fate.selected_key == "drop"):
			self.action += " drop / "
		self.action += " end"
		flow_cmd = self.root.fb.get_attr_arg() + self.root.fb.item.get_item() + self.action
		self.flow_detail.set_text(flow_cmd)
		testpmd.input(flow_cmd)


class FlowBox(flx.PyWidget):

	def init(self):
		self.box=[]
		with flx.VBox(flex=1, style='border:2px solid gray;border-radius: 5px'):
			flx.Label(text='Add flow', flex=1, style='text-align:center')
			with flx.HBox(style='border:2px solid gray;border-radius: 5px'):
				ui.Label(text='attr:')
				self.attr = ui.ComboBox(editable=True, selected_key='ingress', options=('ingress', 'egress', 'transfer'))
				ui.Label(text='port_id:')
				self.port_id = ui.LineEdit(text='0')
				ui.Label(text='group:')
				self.group_id = ui.LineEdit(text='1')
			self.item = ItemBox()
			self.action = ActionBox()

	def get_attr_arg(self):
		self.aarg = "flow create " + self.port_id.text + " group " + self.group_id.text + " " + self.attr.selected_key + " "
		return self.aarg

class ShowBox(flx.PyWidget):

	def init(self):
		self.box=[]
		with flx.VBox(flex=1, style='border:2px solid gray;border-radius: 5px'):
			with flx.HBox(flex=0):
				self.title = flx.Label(text='Interactive:', flex=0, style='text-align:left')
				self.input = flx.LineEdit(placeholder_text='> input testpmd commands', flex=2)
				disabled = False if testpmd.alive else True
				self.input.set_disabled(disabled)
			with flx.HBox(flex=1):
				self.testpmdout=TestPMDOut(flex=1)

	@event.reaction('input.submit')
	def issue_cmd(self, *events):
		testpmd.input(self.input.text + '\n')
		self.input.set_text('')


class FocusBox(flx.VBox):
	@flx.action
	def focus(self):
		self.node.focus()

class TestpmdUI(flx.PyWidget):
	CSS = """
		.flx-MyWidget {
			min-width: 10px;
			min-height: 10px;
			padding: 5px;
			border: 2px solid black;
			border-radius: 5px;
	}
	"""

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
		with flx.VBox(flex=1, style='border:2px solid gray;border-radius: 5px', tabindex=0):
			with flx.VBox(flex=1):
				self.db=DeviceBox(flex=0)
				self.eb=EALBox(flex=0)
				self.ab=APPBox(flex=0)
				self.fb=FlowBox(flex=0)
				self.show=ShowBox(flex=1)

	@testpmd.reaction('!output')
	def print_testpmd_output(self, *events):
		self.show.input.set_disabled(not testpmd.alive)
		for ev in events:
			for line in ev.buffer:
				self.show.testpmdout.add_line(line)

              
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
