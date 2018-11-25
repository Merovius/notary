-- Copyright 2018 Axel Wagner
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- Wireshark dissector for the roughtime protocol

local p_rt = Proto("roughtime", "Roughtime");

local f_nfields = ProtoField.uint16("roughtime.nfields", "Number of fields", base.DEC)
local f_sig = ProtoField.bytes("roughtime.sig", "Signature", base.DOT)
local f_nonc = ProtoField.bytes("roughtime.nonce", "Nonce", base.DOT)
local f_dele = ProtoField.bytes("roughtime.dele", "Delegation", base.DOT)
local f_path = ProtoField.bytes("roughtime.path", "Path", base.DOT)
local f_radi = ProtoField.new("Radius", "roughtime.radi", ftypes.RELATIVE_TIME)
local f_pubk = ProtoField.bytes("roughtime.pubk", "Public key", base.DOT)
local f_midp = ProtoField.new("Midpoint", "roughtime.midp", ftypes.ABSOLUTE_TIME)
local f_srep = ProtoField.bytes("roughtime.srep", "Signed Response", base.DOT)
local f_maxt = ProtoField.new("Maximum valid time", "roughtime.maxt", ftypes.ABSOLUTE_TIME)
local f_root = ProtoField.bytes("roughtime.root", "Root of merkle-tree", base.DOT)
local f_cert = ProtoField.bytes("roughtime.cert", "Certificate", base.DOT)
local f_mint = ProtoField.new("Minimum valid time", "roughtime.mint", ftypes.ABSOLUTE_TIME)
local f_indx = ProtoField.uint32("roughtime.indx", "Index in merkle-tree")
local f_pad = ProtoField.bytes("roughtime.pad", "Padding", base.DOT)
local f_tag = ProtoField.uint16("roughtime.tag", "Unknown field", base.HEX)
local f_field = ProtoField.bytes("roughtime.field", "Value", base.DOT)

p_rt.fields = {
	f_nfields,
	f_sig,
	f_nonc,
	f_dele,
	f_path,
	f_radi,
	f_pubk,
	f_midp,
	f_srep,
	f_maxt,
	f_root,
	f_cert,
	f_mint,
	f_indx,
	f_pad,
	f_tag,
	f_field
}

function p_rt.dissector(buf, pkt, tree)
	local subtree = tree:add(p_rt, buf(0))
	dissect(buf, pkt, subtree)
end

function dissect(buf, pkt, subtree)
	subtree:add_le(f_nfields, buf(0,4))

	local n = buf(0,4):le_uint()
	if n == 0 then
		return
	end
	local start = 0
	for i = 0,n-1 do
		local stop = buf:len()-8*n
		if i < n-1 then
			stop = buf(4*i+4,4):le_uint()
		end
		local tag = buf(4*n+4*i,4)
		local val = buf(start+8*n,stop-start)
		if tag:le_uint() == 0x00474953 then
			subtree:add(f_sig, val)
		elseif tag:string() == "NONC" then
			subtree:add(f_nonc, val)
		elseif tag:string() == "DELE" then
			local dele = subtree:add(f_dele, val)
			dissect(val:tvb(), pkt, dele)
		elseif tag:string() == "PATH" then
			subtree:add(f_path, val)
		elseif tag:string() == "RADI" then
			subtree:add_le(f_radi, val, duration_us(val))
		elseif tag:string() == "PUBK" then
			subtree:add(f_pubk, val)
		elseif tag:string() == "MIDP" then
			subtree:add_le(f_midp, val, time_us(val))
		elseif tag:string() == "SREP" then
			local srep = subtree:add(f_srep, val)
			dissect(val:tvb(), pkt, srep)
		elseif tag:string() == "MAXT" then
			subtree:add_le(f_maxt, val, time_us(val))
		elseif tag:string() == "ROOT" then
			subtree:add(f_root, val)
		elseif tag:string() == "CERT" then
			local cert = subtree:add(f_cert, val)
			dissect(val:tvb(), pkt, cert)
		elseif tag:string() == "MINT" then
			subtree:add(f_mint, val, time_us(val))
		elseif tag:string() == "INDX" then
			subtree:add_le(f_indx, val)
		elseif tag:le_uint() == 0xff444150 then
			subtree:add(f_pad, val)
		else
			subtree:add_le(f_tag, tag)
			subtree:add(f_field, val)
		end
		start = stop
	end
end

function duration_us(buf)
	local t_us = buf:le_uint()
	local s = t_us/1e6
	local ns = t_us%1e6
	return NSTime.new(s, ns)
end

function time_us(buf)
	local t_us = buf:le_uint64()
	local s = (t_us/1e6):tonumber()
	local ns = (t_us%1e6):tonumber()
	return NSTime.new(s, ns)
end

local udp_encap_table = DissectorTable.get("udp.port")

udp_encap_table:add(2002, p_rt)
