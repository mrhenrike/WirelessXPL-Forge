"""wirelessxpl AutoPwn — ble segment. # authorized use only"""
from .base import SegmentAutoPwn
class BleAutoPwn(SegmentAutoPwn):
    def __init__(self, targets, **kw): super().__init__("ble", targets, **kw)
