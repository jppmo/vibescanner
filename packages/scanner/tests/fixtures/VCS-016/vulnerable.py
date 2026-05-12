import xml.etree.ElementTree as ET
from xml.dom import minidom
from lxml import etree

def parse_user_xml(xml_string):
    root = ET.fromstring(xml_string)
    return root.tag

def parse_dom(path):
    return minidom.parse(path)

def parse_with_lxml(text):
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(text, parser)
