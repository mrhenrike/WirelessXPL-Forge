--------------------------------------------------------------------------
--
-- Ubisense UWB Protocol Plug-in for Wireshark
--
-- date    : June, 26th 2023
-- author  : Andrea Palanca
-- contact : labs [ @ ] nozominetworks [ . ] com
--
--------------------------------------------------------------------------

proto_ubisense_uwb = Proto("ubisense_uwb","Ubisense UWB Protocol")
children_table = DissectorTable.new("ubisense_uwb.children", "ubisense_uwb.children", ftypes.UINT32, base.DEC, ubisense_uwb) -- Children table contains all children protocols for dissecting the various message codes. Currently, only 0x026B message code (D4 Tag Location) is supported

message_codes = {
    [0x26b] = "D4 Tag Location"
}

base_protofields =
{
    magic_number = ProtoField.uint16("ubisense_uwb.magic_number", "Magic Number", base.HEX),
    message_code = ProtoField.uint16("ubisense_uwb.message_code", "Message Code", base.HEX, message_codes)
}

proto_ubisense_uwb.fields = base_protofields

base_fields =
{
    message_code_field = Field.new("ubisense_uwb.message_code")
}

base_experts =
{
    missing_code_dissector = ProtoExpert.new("ubisense_uwb.missing_code_dissector.expert", "Missing code dissector", expert.group.UNDECODED, expert.severity.WARN)
}

proto_ubisense_uwb.experts = base_experts

function heuristic_checker(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    magic_number = buffer(0,2)
    if magic_number:uint() == 58008 then -- 0xe298
        proto_ubisense_uwb.dissector(buffer, pinfo, tree)
        return true
    end
end

function proto_ubisense_uwb.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = proto_ubisense_uwb.name
    local root = tree:add(proto_ubisense_uwb, buffer(), "Ubisense UWB Protocol")
    root:add(base_protofields["magic_number"], buffer(0,2))
    root:add(base_protofields["message_code"], buffer(2,2))
    local message_code_value = base_fields["message_code_field"]()()
    local body_length_value = buffer:reported_length_remaining(4)
    local bodySubtree = root:add(proto_ubisense_uwb, buffer(4, body_length_value), "Body")
    local child = children_table:get_dissector(message_code_value)
    local body_buffer = buffer(4, body_length_value):tvb()
    if child ~= nil then
        child(body_buffer, pinfo, bodySubtree)
    else
        bodySubtree:add_proto_expert_info(base_experts["missing_code_dissector"])
    end
end

proto_ubisense_uwb:register_heuristic("udp", heuristic_checker)

proto_ubisense_uwb_d4tagloc = Proto("ubisense_uwb.d4tagloc","Ubisense UWB Protocol - D4 Tag Location packet")

d4tagloc_protofields =
{
    tagId = ProtoField.uint64("ubisense_uwb.d4tagloc.tagid", "Tag ID", base.HEX),
    flags = ProtoField.uint32("ubisense_uwb.d4tagloc.flags", "Flags", base.HEX),
    xCord = ProtoField.float("ubisense_uwb.d4tagloc.xcord", "X Coordinate"),
    yCord = ProtoField.float("ubisense_uwb.d4tagloc.ycord", "Y Coordinate"),
    zCord = ProtoField.float("ubisense_uwb.d4tagloc.zcord", "Z Coordinate"),
    error = ProtoField.float("ubisense_uwb.d4tagloc.error", "Error"),
    unixNanosTimestamp = ProtoField.uint64("ubisense_uwb.d4tagloc.unixnanostimestamp", "Unix Timestamp in Nanoseconds"),
    time = ProtoField.absolute_time("ubisense_uwb.d4tagloc.time", "Time", base.LOCAL)
}

proto_ubisense_uwb_d4tagloc.fields = d4tagloc_protofields

d4tagloc_fields =
{
    unixNanosTimestamp_field = Field.new("ubisense_uwb.d4tagloc.unixnanostimestamp")
}

function proto_ubisense_uwb_d4tagloc.dissector(buffer, pinfo, tree)
    tree:add(d4tagloc_protofields["tagId"], buffer(0,8))
    tree:add(d4tagloc_protofields["flags"], buffer(8,4))
    tree:add_le(d4tagloc_protofields["xCord"], buffer(12,4))
    tree:add_le(d4tagloc_protofields["yCord"], buffer(16,4))
    tree:add_le(d4tagloc_protofields["zCord"], buffer(20,4))
    tree:add_le(d4tagloc_protofields["error"], buffer(24,4))
    tree:add(d4tagloc_protofields["unixNanosTimestamp"], buffer(28,8))
    local unixNanosTimestamp_value = d4tagloc_fields["unixNanosTimestamp_field"]()()
    local unixNanosTimestamp_value_seconds = (unixNanosTimestamp_value / 1e9):tonumber()
    local unixNanosTimestamp_value_nanoseconds = (unixNanosTimestamp_value % 1e9):tonumber()
    tree:add(d4tagloc_protofields["time"], buffer(28,8), NSTime.new(unixNanosTimestamp_value_seconds, unixNanosTimestamp_value_nanoseconds)):set_generated()
    pinfo.cols.info = "D4 Tag Location"
end

DissectorTable.get("ubisense_uwb.children"):add(0x26b, proto_ubisense_uwb_d4tagloc)