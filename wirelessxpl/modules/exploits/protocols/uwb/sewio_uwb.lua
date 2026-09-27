--------------------------------------------------------------------------
--
-- Sewio UWB Protocol Plug-in for Wireshark
--
-- date    : August, 10th 2022
-- author  : Luca Cremona
-- contact : labs [ @ ] nozominetworks [ . ] com
--
--------------------------------------------------------------------------

proto_sewio_uwb = Proto("sewio_uwb","Sewio UWB Protocol")

protofields =
{
	separator 			= ProtoField.uint8("sewio_uwb.separator", "Separator", base.HEX),
	crc16 				= ProtoField.uint16("sewio_uwb.crc16", "Data CRC", base.HEX),
	report_len 			= ProtoField.uint16("sewio_uwb.report_length", "Report Length", base.HEX),
	anchorMac			= ProtoField.new("Anchor Mac", "sewio_uwb.anchormac", ftypes.STRING),
	reportType 			= ProtoField.new("Report Type", "sewio_uwb.reporttype", ftypes.STRING),
	blinkData			= ProtoField.new("Blink Data", "sewio_uwb.blinkdata", ftypes.STRING),
	optLen 				= ProtoField.uint16("sewio_uwb.optlen", "Option Length", base.HEX),
	fcode 				= ProtoField.uint8("sewio_uwb.fcode", "Function Code", base.HEX),
	deviceID			= ProtoField.new("Device ID", "sewio_uwb.deviceid", ftypes.STRING),
	seqNum 				= ProtoField.uint8("sewio_uwb.seqnum", "Sequence Number", base.HEX),
	SGSeqNum 			= ProtoField.uint8("sewio_uwb.sgseqnum", "Sync Group Sequence Number", base.HEX),
	UWBTimestamp 		= ProtoField.uint64("sewio_uwb.uwbtimestamp", "UWB Timestamp", base.DEC),
	maxNoise 			= ProtoField.uint16("sewio_uwb.maxnoise", "Maximum Noise", base.HEX),
	firstPathAmp1 		= ProtoField.uint16("sewio_uwb.firstpathamp1", "First Path Amp 1", base.HEX),
	stdNoise 			= ProtoField.uint16("sewio_uwb.stdnoise", "Standard Noise", base.HEX),
	firstPathAmp2 		= ProtoField.uint16("sewio_uwb.firstpathamp2", "First Path Amp 2", base.HEX),
	firstPathAmp3 		= ProtoField.uint16("sewio_uwb.firstpathamp3", "First Path Amp 3", base.HEX),
	maxGrowthCir		= ProtoField.uint16("sewio_uwb.maxgrowtcir", "Maximum Growth CIR", base.HEX),
	rxPreamCount 		= ProtoField.uint16("sewio_uwb.rxpreamcount", "Rx Pream Count", base.HEX),
	firstPathIndex		= ProtoField.uint16("sewio_uwb.firstpathindex", "First Path Index", base.HEX),
	peakPathIndex 		= ProtoField.uint16("sewio_uwb.peakpathindex", "Peak Path Index", base.HEX),
	peakPathAmp 		= ProtoField.uint16("sewio_uwb.peakpathamp", "Peak Path Amp", base.HEX),
	noiseThrMulti		= ProtoField.uint8("sewio_uwb.noisethrmulti", "Noise Thr Multi", base.HEX),
	numSamplesCIR 		= ProtoField.uint8("sewio_uwb.numsamplescir", "Number of Samples CIR", base.HEX),
	fPIndexInSamples 	= ProtoField.uint8("sewio_uwb.fpindexinsamples", "fP Index In Samples", base.HEX),
	UWBTemp				= ProtoField.uint8("sewio_uwb.uwbtemp", "UWB Temp", base.HEX),
	barometerData		= ProtoField.int32("sewio_uwb.barometerdata", "Barometer Data", base.DEC),
	remoteID			= ProtoField.new("Remote ID", "sewio_uwb.remoteid", ftypes.STRING),
	twrSeqNum 			= ProtoField.uint16("sewio_uwb.twrseqnum", "TWR Sequence Number", base.HEX),
	replyDelayUs 		= ProtoField.uint32("sewio_uwb.replydelayus", "Replay Delay US", base.HEX),
	tmstTxPoll 			= ProtoField.uint64("sewio_uwb.tmsttxpoll", "TMST Tx Poll", base.HEX),
	tmstRxResp 			= ProtoField.uint64("sewio_uwb.tmstrxresp", "TMST RX Resp", base.HEX),
	rfConf 				= ProtoField.uint8("sewio_uwb.rfconf", "RF Conf", base.HEX),
	rawDwTemp 			= ProtoField.uint8("sewio_uwb.dwtemp", "DW Temp", base.HEX),

	respMaxNoise 		= ProtoField.uint16("sewio_uwb.respmaxnoise", "Resp Max Noise", base.HEX),
	respFirstPathAmp1 	= ProtoField.uint16("sewio_uwb.respfirstpathamp1", "Resp First Path Amp 1", base.HEX),
	respStdNoise 		= ProtoField.uint16("sewio_uwb.respstdnoise", "Resp Std. Noise", base.HEX),
	respFirstPathAmp2 	= ProtoField.uint16("sewio_uwb.respfirstpathamp2", "Resp First Path Amp 2", base.HEX),
	respFirstPathAmp3	= ProtoField.uint16("sewio_uwb.respfirstpathamp3", "Resp First Path Amp 3", base.HEX),
	respMaxGrowthCir 	= ProtoField.uint16("sewio_uwb.respmaxgrowthcir", "Resp Maximum Growth CIR", base.HEX),
	respRxPreamCount 	= ProtoField.uint16("sewio_uwb.resppreamcount", "Respo Pream Count", base.HEX),
	respFirstPathIndex 	= ProtoField.uint16("sewio_uwb.respfirstpathindex", "Resp First Path Index", base.HEX),

	pollMaxNoise 		= ProtoField.uint16("sewio_uwb.pollmaxnoise", "Poll Max Noise", base.HEX),
	pollFirstPathAmp1 	= ProtoField.uint16("sewio_uwb.pollfirstpathamp1", "Poll First Path Amp 1", base.HEX),
	pollStdNoise 		= ProtoField.uint16("sewio_uwb.pollstdnoise", "Poll Std. Noise", base.HEX),
	pollFirstPathAmp2 	= ProtoField.uint16("sewio_uwb.pollfirstpathamp2", "Poll First Path Amp 2", base.HEX),
	pollFirstPathAmp3	= ProtoField.uint16("sewio_uwb.pollfirstpathamp3", "Poll First Path Amp 3", base.HEX),
	pollMaxGrowthCir 	= ProtoField.uint16("sewio_uwb.pollmaxgrowthcir", "Poll Maximum Growth CIR", base.HEX),
	pollRxPreamCount 	= ProtoField.uint16("sewio_uwb.pollpreamcount", "Poll Pream Count", base.HEX),
	pollFirstPathIndex 	= ProtoField.uint16("sewio_uwb.pollfirstpathindex", "Poll First Path Index", base.HEX),

	finalMaxNoise 		= ProtoField.uint16("sewio_uwb.finalmaxnoise", "Final Max Noise", base.HEX),
	finalFirstPathAmp1 	= ProtoField.uint16("sewio_uwb.finalfirstpathamp1", "Final First Path Amp 1", base.HEX),
	finalStdNoise 		= ProtoField.uint16("sewio_uwb.finalstdnoise", "Final Std. Noise", base.HEX),
	finalFirstPathAmp2 	= ProtoField.uint16("sewio_uwb.finalfirstpathamp2", "Final First Path Amp 2", base.HEX),
	finalFirstPathAmp3	= ProtoField.uint16("sewio_uwb.finalfirstpathamp3", "Final First Path Amp 3", base.HEX),
	finalMaxGrowthCir 	= ProtoField.uint16("sewio_uwb.finalmaxgrowthcir", "Final Maximum Growth CIR", base.HEX),
	finalRxPreamCount 	= ProtoField.uint16("sewio_uwb.finalpreamcount", "Final Pream Count", base.HEX),
	finalFirstPathIndex = ProtoField.uint16("sewio_uwb.finalfirstpathindex", "Final First Path Index", base.HEX),

	period				= ProtoField.uint32("sewio_uwb.period", "Period", base.HEX)
}

proto_sewio_uwb.fields = protofields

ip_addr_f = Field.new("ip.src")

function heuristic_checker(buffer, pinfo, tree)
	if buffer:len() == 0 then return end
	proto_id = buffer(0,1)
	if proto_id:uint() == 35 then
		proto_sewio_uwb.dissector(buffer, pinfo, tree)
		return true
	end 
end

function proto_sewio_uwb.dissector(buffer, pinfo, tree)
	length = buffer:len()
	if length == 0 then return end
	pinfo.cols.protocol = proto_sewio_uwb.name
	local subtree = tree:add(proto_sewio_uwb, buffer(), "Sewio UWB Protocol")
	subtree:add(protofields["separator"], buffer(0,1))
	subtree:add_le(protofields["crc16"], buffer(1,2))
	reportLength = buffer(3 , 2):le_uint()
	local offset = 0
	local buffer1
	local singleReport
	while (offset + reportLength +2 < length)
	do
		buffer1 = buffer(offset, reportLength + 5)
		reportLength = buffer1(3 , 2):le_uint()
		singleReport = buffer1(3)
		parseReportUniversal(singleReport, pinfo, subtree)
		offset = offset + reportLength + 5
	end
end

function parseReportUniversal(reportBuffer, pinfo, subtree)
	subtree:add_le(protofields["report_len"], reportBuffer(0,2))
	mac_1 = reportBuffer(7,1)
	mac_2 = reportBuffer(6,1)
	mac_3 = reportBuffer(5,1)
	mac_4 = reportBuffer(4,1)
	mac_5 = reportBuffer(3,1)
	mac_6 = reportBuffer(2,1)
	subtree:add(protofields["anchorMac"], reportBuffer(2,6), string.format("%0.2x:%0.2x:%0.2x:%0.2x:%0.2x:%0.2x", 
	mac_1:uint(), mac_2:uint(), mac_3:uint(), mac_4:uint(), mac_5:uint(), mac_6:uint()))
	subtree:add(protofields["reportType"], reportBuffer(8,1))
	local optionsLength = reportBuffer:len()-9
	local optionsData = reportBuffer(9, optionsLength)
	local options_tree = subtree:add(proto_sewio_uwb, reportBuffer(), "Options" )
	local calcLength = 0
	local options = {}
	local optionsOk = true
	local length = 0
	local oneOptionData = 0
	local i = 0
	repeat
		length = optionsData(1,2):le_uint()
		oneOptionData = optionsData(0, length+3)
		calcLength = calcLength + length + 3
		if (calcLength > optionsLength) then
			optionsOk = false
    	end
    	if (optionsOk == true) then
        	options[i] = oneOptionData
			decode_option(options[i], pinfo, options_tree)
			if optionsData:len() > length+3 then
	        	optionsData = optionsData(length + 3, optionsData:len() - length - 3)
			else
				optionsdata = {}
			end
    	end
		i = i + 1
	until optionsData:len() == 0 or optionsOk == false
end

function decode_option(option, pinfo, options_tree)
	option_id = option(0,1):uint()
	local optionDescriptor
	if option_id == 0 then
		decodeSyncEmission(option, pinfo, options_tree)
	elseif option_id == 1 then
		decodeSyncArrival(option, pinfo, options_tree)
	elseif option_id == 2 then
		decodeBlink(option, pinfo, options_tree)
	elseif option_id == 3 then
		decodeBlinkExtended(option, pinfo, options_tree)
	elseif option_id == 4 then
		decodeCIR(option, pinfo, options_tree)
	elseif option_id == 5 then
		decodeSyncInfo(option, pinfo, options_tree)
	elseif option_id == 6 then
		decodeDWTemp(option, pinfo, options_tree)
	elseif option_id == 7 then
		decodeBarometer(option, pinfo, options_tree)
	elseif option_id == 8 then
		decodeTWRInitiator(option, pinfo, options_tree)
	elseif option_id == 9 then
		decodeTWRRemote(option, pinfo, options_tree)
	elseif option_id == 10 then
		decodeSyncDiscoveryEmission(option, pinfo, options_tree)
	elseif option_id == 11 then
		decodeSyncDiscoveryArrival(option, pinfo, options_tree)
	elseif option_id == 12 then
		decodeUdpAd(option, pinfo, options_tree)
	else
		optionDescriptor = "Report Universal: Unknown option"
		local opTree = options_tree:add(proto_sewio_uwb, option(), optionDescriptor)
	end
end

function decodeSyncEmission(option, pinfo, options_tree) 
	local optionDescriptor = "SyncEmission" 
	local opTree = options_tree:add(proto_sewio_uwb, option(), optionDescriptor)
	opTree:add_le(protofields["optLen"], option(1,2))
	opTree:add(protofields["fcode"], option(3,1))
	mac_1 = option(9,1)
	mac_2 = option(8,1)
	mac_3 = option(7,1)
	mac_4 = option(6,1)
	mac_5 = option(5,1)
	mac_6 = option(4,1)
	opTree:add(protofields["deviceID"], option(4,6), string.format("%0.2x:%0.2x:%0.2x:%0.2x:%0.2x:%0.2x", 
	mac_1:uint(), mac_2:uint(), mac_3:uint(), mac_4:uint(), mac_5:uint(), mac_6:uint()))
	opTree:add(protofields["seqNum"], option(10,1))
	opTree:add(protofields["SGSeqNum"], option(11,1))
	opTree:add_le(protofields["UWBTimestamp"], option(12,8))
	sequenceID = option(10,1)
	sgsequenceID = option(11,1)
	value = option(12,8):le_uint64()
	local ip = tostring(ip_addr_f())
end

function decodeSyncArrival(option, pinfo, options_tree) 
	local optionDescriptor = "SyncArrival" 
	local opTree = options_tree:add(proto_sewio_uwb, option(), optionDescriptor)
	opTree:add_le(protofields["optLen"], option(1,2))
	opTree:add(protofields["fcode"], option(3,1))
	mac_1 = option(9,1)
	mac_2 = option(8,1)
	mac_3 = option(7,1)
	mac_4 = option(6,1)
	mac_5 = option(5,1)
	mac_6 = option(4,1)
	opTree:add(protofields["deviceID"], option(4,6), string.format("%0.2x:%0.2x:%0.2x:%0.2x:%0.2x:%0.2x", 
	mac_1:uint(), mac_2:uint(), mac_3:uint(), mac_4:uint(), mac_5:uint(), mac_6:uint()))
	opTree:add(protofields["seqNum"], option(10,1))
	opTree:add(protofields["SGSeqNum"], option(11,1))
	opTree:add_le(protofields["UWBTimestamp"], option(12,8))
	opTree:add_le(protofields["maxNoise"], option(20,2))
	opTree:add_le(protofields["firstPathAmp1"], option(22,2))
	opTree:add_le(protofields["stdNoise"], option(24,2))
	opTree:add_le(protofields["firstPathAmp2"], option(26,2))
	opTree:add_le(protofields["firstPathAmp3"], option(28,2))
	opTree:add_le(protofields["maxGrowthCir"], option(30,2))
	opTree:add_le(protofields["rxPreamCount"], option(32,2))
	opTree:add_le(protofields["firstPathIndex"], option(34,2))
	sequenceID = option(10,1)
	sgsequenceID = option(11,1)
	value = option(12,8):le_uint64()
	local ip = tostring(ip_addr_f())
end

function decodeBlink(option, pinfo, options_tree)
	local optionDescriptor = "Blink" 
	local opTree = options_tree:add(proto_sewio_uwb, option(), optionDescriptor) 
	opTree:add_le(protofields["optLen"], option(1,2))
	opTree:add(protofields["fcode"], option(3,1))
	mac_1 = option(9,1)
	mac_2 = option(8,1)
	mac_3 = option(7,1)
	mac_4 = option(6,1)
	mac_5 = option(5,1)
	mac_6 = option(4,1)
	opTree:add(protofields["deviceID"], option(4,6), string.format("%0.2x:%0.2x:%0.2x:%0.2x:%0.2x:%0.2x", 
	mac_1:uint(), mac_2:uint(), mac_3:uint(), mac_4:uint(), mac_5:uint(), mac_6:uint()))
	opTree:add(protofields["seqNum"], option(10,1))
	opTree:add_le(protofields["UWBTimestamp"], option(11,8))
	opTree:add_le(protofields["maxNoise"], option(19,2))
	opTree:add_le(protofields["firstPathAmp1"], option(21,2))
	opTree:add_le(protofields["stdNoise"], option(23,2))
	opTree:add_le(protofields["firstPathAmp2"], option(25,2))
	opTree:add_le(protofields["firstPathAmp3"], option(27,2))
	opTree:add_le(protofields["maxGrowthCir"], option(29,2))
	opTree:add_le(protofields["rxPreamCount"], option(31,2))
	opTree:add_le(protofields["firstPathIndex"], option(33,2))
	sequenceID = option(10,1)
	value = option(11,8):le_uint64()
	local ip = tostring(ip_addr_f())
end

function decodeBlinkExtended(option, pinfo, options_tree) 
	local optionDescriptor = "Blink Extended" 
	local opTree = options_tree:add(proto_sewio_uwb, option(), optionDescriptor)
	opTree:add_le(protofields["optLen"], option(1,2))
	opTree:add(protofields["blinkData"], option(3,option(1,2):le_uint()))
end

function decodeCIR(option, pinfo, options_tree) 
	local optionDescriptor = "CIR" 
	local opTree = options_tree:add(proto_sewio_uwb, option(), optionDescriptor)
	opTree:add_le(protofields["optLen"], option(1,2))
	opTree:add_le(protofields["peakPathIndex"], option(3,2))
	opTree:add_le(protofields["peakPathAmp"], option(5,2))
	opTree:add(protofields["noiseThrMulti"], option(7,1))
	opTree:add(protofields["numSamplesCIR"], option(8,1))
	opTree:add(protofields["fPIndexInSamples"], option(9,1))
	-- Additional data are skipped, as they are not used by Sewio
end

function decodeSyncInfo(option, pinfo, options_tree) 
	local optionDescriptor = "SyncInfo" 
	local opTree = options_tree:add(proto_sewio_uwb, option(), optionDescriptor)
	opTree:add_le(protofields["optLen"], option(1,2))
	opTree:add(protofields["fcode"], option(3,1))
	mac_1 = option(9,1)
	mac_2 = option(8,1)
	mac_3 = option(7,1)
	mac_4 = option(6,1)
	mac_5 = option(5,1)
	mac_6 = option(4,1)
	opTree:add(protofields["deviceID"], option(4,6), string.format("%0.2x:%0.2x:%0.2x:%0.2x:%0.2x:%0.2x", 
	mac_1:uint(), mac_2:uint(), mac_3:uint(), mac_4:uint(), mac_5:uint(), mac_6:uint()))
	opTree:add(protofields["seqNum"], option(10,1))
	opTree:add(protofields["SGSeqNum"], option(11,1))
	opTree:add_le(protofields["UWBTimestamp"], option(12,8))
end

function decodeDWTemp(option, pinfo, options_tree) 
	local optionDescriptor = "DWT Temp" 
	local opTree = options_tree:add(proto_sewio_uwb, option(), optionDescriptor)
	opTree:add_le(protofields["optLen"], option(1,2))
	opTree:add(protofields["UWBTemp"], option(3,1))
end

function decodeBarometer(option, pinfo, options_tree) 
	local optionDescriptor = "Barometer" 
	local opTree = options_tree:add(proto_sewio_uwb, option(), optionDescriptor)
	opTree:add_le(protofields["optLen"], option(1,2))
	opTree:add_le(protofields["barometerData"], option(3,4))
end

function decodeTWRInitiator(option, pinfo, options_tree) 
	local optionDescriptor = "TWR Initiator" 
	local opTree = options_tree:add(proto_sewio_uwb, option(), optionDescriptor)
	opTree:add_le(protofields["optLen"], option(1,2))
	opTree:add(protofields["fcode"], option(3,1))
	mac_1 = option(9,1)
	mac_2 = option(8,1)
	mac_3 = option(7,1)
	mac_4 = option(6,1)
	mac_5 = option(5,1)
	mac_6 = option(4,1)
	opTree:add(protofields["remoteID"], option(4,6), string.format("%0.2x:%0.2x:%0.2x:%0.2x:%0.2x:%0.2x", 
	mac_1:uint(), mac_2:uint(), mac_3:uint(), mac_4:uint(), mac_5:uint(), mac_6:uint()))
	opTree:add_le(protofields["TWRSeqNum"], option(10,2))
	opTree:add_le(protofields["replyDelayUs"], option(12,4))
	opTree:add_le(protofields["tmstTxPoll"], option(16,8))
	opTree:add_le(protofields["tmstRxResp"], option(24,8))
	opTree:add(protofields["rfConf"], option(32,1))
	opTree:add(protofields["rawDwTemp"], option(33,1))
	opTree:add_le(protofields["respMaxNoise"], option(34,2))
	opTree:add_le(protofields["respFirstPathAmp1"], option(36,2))
	opTree:add_le(protofields["respStdNoise"], option(38,2))
	opTree:add_le(protofields["respFirstPathAmp2"], option(40,2))
	opTree:add_le(protofields["respFirstPathAmp3"], option(42,2))
	opTree:add_le(protofields["respMaxGrowthCir"], option(44,2))
	opTree:add_le(protofields["respRxPreamCount"], option(46,2))
	opTree:add_le(protofields["respFirstPathIndex"], option(48,2))
end

function decodeTWRRemote(option, pinfo, options_tree) 
	local optionDescriptor = "TWR Initiator" 
	local opTree = options_tree:add(proto_sewio_uwb, option(), optionDescriptor)
	opTree:add_le(protofields["optLen"], option(1,2))
	opTree:add(protofields["fcode"], option(3,1))
	mac_1 = option(9,1)
	mac_2 = option(8,1)
	mac_3 = option(7,1)
	mac_4 = option(6,1)
	mac_5 = option(5,1)
	mac_6 = option(4,1)
	opTree:add(protofields["remoteID"], option(4,6), string.format("%0.2x:%0.2x:%0.2x:%0.2x:%0.2x:%0.2x", 
	mac_1:uint(), mac_2:uint(), mac_3:uint(), mac_4:uint(), mac_5:uint(), mac_6:uint()))
	opTree:add_le(protofields["TWRSeqNum"], option(10,2))
	opTree:add_le(protofields["replyDelayUs"], option(12,4))
	opTree:add_le(tmstTRxPoll, option(16,8))
	opTree:add_le(tmstRxFinal, option(24,8))
	opTree:add(protofields["rfConf"], option(32,1))
	opTree:add(protofields["rawDwTemp"], option(33,1))
	opTree:add_le(protofields["pollMaxNoise"], option(34,2))
	opTree:add_le(protofields["pollFirstPathAmp1"], option(36,2))
	opTree:add_le(protofields["pollStdNoise"], option(38,2))
	opTree:add_le(protofields["pollFirstPathAmp2"], option(40,2))
	opTree:add_le(protofields["pollFirstPathAmp3"], option(42,2))
	opTree:add_le(protofields["pollMaxGrowthCir"], option(44,2))
	opTree:add_le(protofields["pollRxPreamCount"], option(46,2))
	opTree:add_le(protofields["pollFirstPathIndex"], option(48,2))
	opTree:add_le(protofields["finalMaxNoise"], option(50,2))
	opTree:add_le(protofields["finalFirstPathAmp1"], option(52,2))
	opTree:add_le(protofields["finalStdNoise"], option(54,2))
	opTree:add_le(protofields["finalFirstPathAmp2"], option(56,2))
	opTree:add_le(protofields["finalFirstPathAmp3"], option(58,2))
	opTree:add_le(protofields["finalMaxGrowthCir"], option(60,2))
	opTree:add_le(protofields["finalRxPreamCount"], option(62,2))
	opTree:add_le(protofields["finalFirstPathIndex"], option(64,2))
end

function decodeSyncDiscoveryEmission(option, pinfo, options_tree) 
	local optionDescriptor = "SyncDiscoveryEmission" 
	local opTree = options_tree:add(proto_sewio_uwb, option(), optionDescriptor)
	opTree:add_le(protofields["optLen"], option(1,2))
	opTree:add(protofields["fcode"], option(3,1))
	mac_1 = option(9,1)
	mac_2 = option(8,1)
	mac_3 = option(7,1)
	mac_4 = option(6,1)
	mac_5 = option(5,1)
	mac_6 = option(4,1)
	opTree:add(protofields["deviceID"], option(4,6), string.format("%0.2x:%0.2x:%0.2x:%0.2x:%0.2x:%0.2x", 
	mac_1:uint(), mac_2:uint(), mac_3:uint(), mac_4:uint(), mac_5:uint(), mac_6:uint()))
	opTree:add(protofields["seqNum"], option(10,1))
	opTree:add(protofields["SGSeqNum"], option(11,1))
	opTree:add_le(protofields["UWBTimestamp"], option(12,8))
end

function decodeSyncDiscoveryArrival(option, pinfo, options_tree) 
	local optionDescriptor = "SyncDiscoveryArrival" 
	local opTree = options_tree:add(proto_sewio_uwb, option(), optionDescriptor)
	opTree:add_le(protofields["optLen"], option(1,2))
	opTree:add(protofields["fcode"], option(3,1))
	mac_1 = option(9,1)
	mac_2 = option(8,1)
	mac_3 = option(7,1)
	mac_4 = option(6,1)
	mac_5 = option(5,1)
	mac_6 = option(4,1)
	opTree:add(protofields["deviceID"], option(4,6), string.format("%0.2x:%0.2x:%0.2x:%0.2x:%0.2x:%0.2x", 
	mac_1:uint(), mac_2:uint(), mac_3:uint(), mac_4:uint(), mac_5:uint(), mac_6:uint()))
	opTree:add(protofields["seqNum"], option(10,1))
	opTree:add(protofields["SGSeqNum"], option(11,1))
	opTree:add_le(protofields["UWBTimestamp"], option(12,8))
	opTree:add_le(protofields["maxNoise"], option(20,2))
	opTree:add_le(protofields["firstPathAmp1"], option(22,2))
	opTree:add_le(protofields["stdNoise"], option(24,2))
	opTree:add_le(protofields["firstPathAmp2"], option(26,2))
	opTree:add_le(protofields["firstPathAmp3"], option(28,2))
	opTree:add_le(protofields["maxGrowthCir"], option(30,2))
	opTree:add_le(protofields["rxPreamCount"], option(32,2))
	opTree:add_le(protofields["firstPathIndex"], option(34,2))
end

function decodeUdpAd(option, pinfo, options_tree) 
	local optionDescriptor = "Udp Ad" 
	local opTree = options_tree:add(proto_sewio_uwb, option(), optionDescriptor)
	opTree:add_le(protofields["optLen"], option(1,2))
	opTree:add_le(protofields["period"], option(3,4))
end

proto_sewio_uwb:register_heuristic("udp", heuristic_checker)