"""wirelessxpl AutoPwn — drone segment. # authorized use only"""
from .base import SegmentAutoPwn
class DroneAutoPwn(SegmentAutoPwn):
    def __init__(self, targets, **kw): super().__init__("drone", targets, **kw)
