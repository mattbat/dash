import datetime
import requests
import logging
import ConfigParser
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


base_path = sys.path[0]
ifttt_key = ""

ziplock_url = 'https://maker.ifttt.com/trigger/ziplock_button/with/key/'
orbit_url = 'https://maker.ifttt.com/trigger/orbit_button/with/key/'

def ziplock_button_pressed():
  current_time = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S')
  print 'Ziplock Dash button pressed at ' + current_time
  global ifttt_key
  url = ziplock_url + ifttt_key
  post_response = requests.post(url=url)
  
def orbit_button_pressed():
  current_time = datetime.datetime.strftime(datetime.datetime.now(), '%Y-%m-%d %H:%M:%S')
  print 'Oribt Dash button pressed at ' + current_time
  global ifttt_key
  url = orbit_url + ifttt_key
  post_response = requests.post(url=url)

def udp_filter(pkt):
  options = pkt[DHCP].options
  for option in options:
    if isinstance(option, tuple):
      if 'requested_addr' in option:
        # we've found the IP address, which means its the second and final UDP request, so we can trigger our action
        mac_to_action[pkt.src]()
        break


mac_to_action = {
	'0c:47:c9:34:ee:e8' : ziplock_button_pressed, 
	'74:c2:46:b7:4e:79' : orbit_button_pressed
	}
	
mac_id_list = list(mac_to_action.keys())



def main():
    Config = ConfigParser.ConfigParser()
    Config.read(base_path + "/config.ini")
    section = "UserConfig"
    global ifttt_key
    ifttt_key = Config.get(section, 'ifttt_key')


main()


print "Waiting for a button press..."
sniff(prn=udp_filter, store=0, filter="udp", lfilter=lambda d: d.src in mac_id_list)
