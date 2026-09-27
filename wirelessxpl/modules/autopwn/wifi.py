"""wirelessxpl AutoPwn — wifi segment. # authorized use only"""
from .base import SegmentAutoPwn
class WifiAutoPwn(SegmentAutoPwn):
    def __init__(self, targets, **kw): super().__init__("wifi", targets, **kw)
