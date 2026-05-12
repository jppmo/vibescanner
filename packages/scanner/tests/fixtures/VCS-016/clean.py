from defusedxml.ElementTree import fromstring, parse
from defusedxml import minidom

def parse_user_xml(xml_string):
    root = fromstring(xml_string)
    return root.tag

def parse_dom(path):
    return minidom.parse(path)
