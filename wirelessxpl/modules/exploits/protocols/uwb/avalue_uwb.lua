--------------------------------------------------------------------------
--
-- Avalue UWB Protocol Plug-in for Wireshark
--
-- date    : August, 10th 2022
-- author  : Andrea Palanca
-- contact : labs [ @ ] nozominetworks [ . ] com
--
--------------------------------------------------------------------------

proto_avalue_uwb = Proto("avalue_uwb","Avalue UWB Protocol")
children_table = DissectorTable.new("avalue_uwb.children", "avalue_uwb.children", ftypes.UINT32, base.DEC, avalue_uwb) -- Children table contains all children protocols for dissecting the various body types. Currently, only CCP and TDoA are supported

packet_types = 
{
    [0] = "None/Anchor Function ACK",
    [16] = "ToF",
    [17] = "TDoA",
    [18] = "SOS",
    [19] = "CCP",
    [20] = "Anchor Command",
    [21] = "Ranging Listening",
    [32] = "Anchor Registration",
    [33] = "Tag Registration",
    [-96] = "Heartbeat",
    [-95] = "Anchor Exploration",
    [-80] = "Reboot",
    [-79] = "Upgrade",
    [-78] = "Restore Configuration",
    [48] = "Anchor Function Configuration",
    [54] = "Mutual Ranging",
    [55] = "Anchor UWB Module Configuration",
    [56] = "Slave Anchor ID Config",
    [57] = "Anchor Group Config",
    [58] = "Static Time Slicing Config",
    [60] = "Dynamic Time Slicing Config",
    [61] = "System Sync Config",
    [102] = "Response",
    [103] = "UWB Debug",
    [112] = "WiFi Enable",
    [113] = "WiFi Configuration",
    [114] = "Anchor IP Configuration",
    [115] = "UWB RF Gateway Configuration",
    [80] = "UWB Module Query",
    [116] = "Network Configuration Query"
}

base_protofields =
{
    separator = ProtoField.uint16("avalue_uwb.separator", "Separator", base.HEX),
    packet_type = ProtoField.int8("avalue_uwb.packet_type", "Packet Type", base.DEC, packet_types),
    body_length = ProtoField.uint8("avalue_uwb.body_length", "Body Length", base.HEX),
    checksum = ProtoField.uint16("avalue_uwb.checksum", "Checksum", base.HEX)
}

proto_avalue_uwb.fields = base_protofields

base_fields =
{
    packet_type_field = Field.new("avalue_uwb.packet_type"),
    body_length_field = Field.new("avalue_uwb.body_length")
}

base_experts =
{
    missing_body_dissector = ProtoExpert.new("avalue_uwb.missing_body_dissector.expert", "Missing body dissector", expert.group.UNDECODED, expert.severity.WARN)
}

proto_avalue_uwb.experts = base_experts

function heuristic_checker(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    separator = buffer(0,2)
    if separator:uint() == 22360 then -- 0x5758
        proto_avalue_uwb.dissector(buffer, pinfo, tree)
        return true
    end 
end

function proto_avalue_uwb.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = proto_avalue_uwb.name
    local root = tree:add(proto_avalue_uwb, buffer(), "Avalue UWB Protocol")
    root:add(base_protofields["separator"], buffer(0,2))
    root:add_le(base_protofields["packet_type"], buffer(2,1))
    root:add_le(base_protofields["body_length"], buffer(3,1))
    local packet_type_value = base_fields["packet_type_field"]()()    
    local body_length_value = base_fields["body_length_field"]()()
    local bodySubtree = root:add(proto_avalue_uwb, buffer(4, body_length_value), "Body")
    local child = children_table:get_dissector(packet_type_value)
    local body_buffer = buffer(4, body_length_value):tvb()
    if child ~= nil then
        child(body_buffer, pinfo, bodySubtree)
    else
        bodySubtree:add_proto_expert_info(base_experts["missing_body_dissector"])
    end
    root:add_le(base_protofields["checksum"], buffer(4 + body_length_value, 2))
end

proto_avalue_uwb:register_heuristic("udp", heuristic_checker)

proto_avalue_uwb_tdoa = Proto("avalue_uwb.tdoa","Avalue UWB Protocol - TDoA packet")

tdoa_protofields =
{
    order = ProtoField.uint16("avalue_uwb.tdoa.order", "Order"),
    tagId = ProtoField.uint64("avalue_uwb.tdoa.tagid", "Tag ID", base.HEX),
    anchorId = ProtoField.uint64("avalue_uwb.tdoa.anchorid", "Anchor ID", base.HEX),
    syncTimestamp = ProtoField.double("avalue_uwb.tdoa.synctimestamp", "Sync Timestamp"),
    eventData = ProtoField.uint8("avalue_uwb.tdoa.eventdata", "Event Data"),
    batData = ProtoField.uint8("avalue_uwb.tdoa.batdata", "Battery Data"),
    firstPathAmp1 = ProtoField.uint16("avalue_uwb.tdoa.firstpathamp1", "First Path Amp 1"),
    firstPathAmp2 = ProtoField.uint16("avalue_uwb.tdoa.firstpathamp2", "First Path Amp 2"),
    firstPathAmp3 = ProtoField.uint16("avalue_uwb.tdoa.firstpathamp3", "First Path Amp 3"),
    maxGrowthCIR = ProtoField.uint16("avalue_uwb.tdoa.maxgrowthcir", "Maximum Growth CIR"),
    rxPreamCount = ProtoField.uint16("avalue_uwb.tdoa.rxpreamcount", "Rx Pream Count"),
    extType = ProtoField.uint8("avalue_uwb.tdoa.exttype", "Extra Data Type"),
    extLen = ProtoField.uint8("avalue_uwb.tdoa.extlen", "Extra Data Length")
}

proto_avalue_uwb_tdoa.fields = tdoa_protofields

tdoa_fields =
{
    order_field = Field.new("avalue_uwb.tdoa.order"),
    tagId_field = Field.new("avalue_uwb.tdoa.tagid"),
    firstPathAmp1_field = Field.new("avalue_uwb.tdoa.firstpathamp1"),
    firstPathAmp2_field = Field.new("avalue_uwb.tdoa.firstpathamp2"),
    firstPathAmp3_field = Field.new("avalue_uwb.tdoa.firstpathamp3"),
    maxGrowthCIR_field = Field.new("avalue_uwb.tdoa.maxgrowthcir"),
    rxPreamCount_field = Field.new("avalue_uwb.tdoa.rxpreamcount")
}

function proto_avalue_uwb_tdoa.dissector(buffer, pinfo, tree)
    tree:add_le(tdoa_protofields["order"], buffer(0,2))
    tree:add_le(tdoa_protofields["tagId"], buffer(2,8))
    tree:add_le(tdoa_protofields["anchorId"], buffer(10,8))
    tree:add_le(tdoa_protofields["syncTimestamp"], buffer(18,8))
    tree:add_le(tdoa_protofields["eventData"], buffer(26,1))
    tree:add_le(tdoa_protofields["batData"], buffer(27,1))
    tree:add_le(tdoa_protofields["firstPathAmp1"], buffer(28,2))
    tree:add_le(tdoa_protofields["firstPathAmp2"], buffer(30,2))
    tree:add_le(tdoa_protofields["firstPathAmp3"], buffer(32,2))
    tree:add_le(tdoa_protofields["maxGrowthCIR"], buffer(34,2))
    tree:add_le(tdoa_protofields["rxPreamCount"], buffer(36,2))
    local firstPathAmp1_value = tdoa_fields["firstPathAmp1_field"]()()
    local firstPathAmp2_value = tdoa_fields["firstPathAmp2_field"]()()
    local firstPathAmp3_value = tdoa_fields["firstPathAmp3_field"]()()
    local maxGrowthCIR_value = tdoa_fields["maxGrowthCIR_field"]()()
    local rxPreamCount_value = tdoa_fields["rxPreamCount_field"]()()
    tree:add_le(tdoa_protofields["extType"], buffer(38,1))
    tree:add_le(tdoa_protofields["extLen"], buffer(39,1))
    local order_value = tdoa_fields["order_field"]()()
    local tagId_hex_value = string.format("%X", tonumber(tostring(tdoa_fields["tagId_field"]()()), 10))
    pinfo.cols.info = "TDoA (" .. order_value .. ") - Tag ID: " .. tagId_hex_value
end

DissectorTable.get("avalue_uwb.children"):add(17, proto_avalue_uwb_tdoa)

proto_avalue_uwb_ccp = Proto("avalue_uwb.ccp","Avalue UWB Protocol - CCP packet")

ccp_protofields =
{
    order = ProtoField.uint16("avalue_uwb.ccp.order", "Order"),
    slaveID = ProtoField.uint64("avalue_uwb.ccp.slaveid", "Slave ID", base.HEX),
    masterID = ProtoField.uint64("avalue_uwb.ccp.masterid", "Master ID", base.HEX),
    status = ProtoField.uint8("avalue_uwb.ccp.status", "Status"),
    txsTimestamp = ProtoField.double("avalue_uwb.ccp.txstimestamp", "Txs Timestamp"),
    rxsTimestamp = ProtoField.double("avalue_uwb.ccp.rxstimestamp", "Rxs Timestamp"),
    firstPathAmp1 = ProtoField.uint16("avalue_uwb.ccp.firstpathamp1", "First Path Amp 1"),
    firstPathAmp2 = ProtoField.uint16("avalue_uwb.ccp.firstpathamp2", "First Path Amp 2"),
    firstPathAmp3 = ProtoField.uint16("avalue_uwb.ccp.firstpathamp3", "First Path Amp 3"),
    maxGrowthCIR = ProtoField.uint16("avalue_uwb.ccp.maxgrowthcir", "Maximum Growth CIR"),
    rxPreamCount = ProtoField.uint16("avalue_uwb.ccp.rxpreamcount", "Rx Pream Count"),
    extType = ProtoField.uint8("avalue_uwb.ccp.exttype", "Extra Data Type"),
    extLen = ProtoField.uint8("avalue_uwb.ccp.extlen", "Extra Data Length")
}

proto_avalue_uwb_ccp.fields = ccp_protofields

ccp_fields =
{
    order_field = Field.new("avalue_uwb.ccp.order"),
    firstPathAmp1_field = Field.new("avalue_uwb.ccp.firstpathamp1"),
    firstPathAmp2_field = Field.new("avalue_uwb.ccp.firstpathamp2"),
    firstPathAmp3_field = Field.new("avalue_uwb.ccp.firstpathamp3"),
    maxGrowthCIR_field = Field.new("avalue_uwb.ccp.maxgrowthcir"),
    rxPreamCount_field = Field.new("avalue_uwb.ccp.rxpreamcount")
}

function proto_avalue_uwb_ccp.dissector(buffer, pinfo, tree)
    tree:add_le(ccp_protofields["order"], buffer(0,2))
    tree:add_le(ccp_protofields["slaveID"], buffer(2,8))
    tree:add_le(ccp_protofields["masterID"], buffer(10,8))
    tree:add_le(ccp_protofields["status"], buffer(18,1))
    tree:add_le(ccp_protofields["txsTimestamp"], buffer(19,8))
    tree:add_le(ccp_protofields["rxsTimestamp"], buffer(27,8))
    tree:add_le(ccp_protofields["firstPathAmp1"], buffer(35,2))
    tree:add_le(ccp_protofields["firstPathAmp2"], buffer(37,2))
    tree:add_le(ccp_protofields["firstPathAmp3"], buffer(39,2))
    tree:add_le(ccp_protofields["maxGrowthCIR"], buffer(41,2))
    tree:add_le(ccp_protofields["rxPreamCount"], buffer(43,2))
    local firstPathAmp1_value = ccp_fields["firstPathAmp1_field"]()()
    local firstPathAmp2_value = ccp_fields["firstPathAmp2_field"]()()
    local firstPathAmp3_value = ccp_fields["firstPathAmp3_field"]()()
    local maxGrowthCIR_value = ccp_fields["maxGrowthCIR_field"]()()
    local rxPreamCount_value = ccp_fields["rxPreamCount_field"]()()
    tree:add_le(ccp_protofields["extType"], buffer(45,1))
    tree:add_le(ccp_protofields["extLen"], buffer(46,1))
    local order_value = ccp_fields["order_field"]()()
    pinfo.cols.info = "CCP (" .. order_value .. ")"
end

DissectorTable.get("avalue_uwb.children"):add(19, proto_avalue_uwb_ccp)