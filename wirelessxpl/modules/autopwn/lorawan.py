"""wirelessxpl AutoPwn — lorawan segment. # authorized use only"""
from .base import SegmentAutoPwn
class LorawanAutoPwn(SegmentAutoPwn):
    def __init__(self, targets, **kw): super().__init__("lorawan", targets, **kw)
