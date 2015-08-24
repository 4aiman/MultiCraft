-- multicraft.lua
-- Packet dissector for the UDP-based MultiCraft protocol
-- Copy this to $HOME/.wireshark/plugins/


--
-- MultiCraft
-- Copyright (C) 2011 celeron55, Perttu Ahola <celeron55@gmail.com>
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License along
-- with this program; if not, write to the Free Software Foundation, Inc.,
-- 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
--


-- Table of Contents:
--   Part 1: Client command dissectors (TOSERVER_*)
--   Part 2: Server command dissectors (TOCLIENT_*)
--   Part 3: Wrapper protocol subdissectors
--   Part 4: Wrapper protocol main dissector
--   Part 5: Utility functions




--------------------------------------------
-- Part 1                                 --
-- Client command dissectors (TOSERVER_*) --
--------------------------------------------

multicraft_client_commands = {}
multicraft_client_obsolete = {}

-- TOSERVER_INIT

do
	local f_ser_fmt = ProtoField.uint8("multicraft.client.init_ser_version",
		"Maximum serialization format version", base.DEC)
	local f_player_name = ProtoField.stringz("multicraft.client.init_player_name", "Player Name")
	local f_password = ProtoField.stringz("multicraft.client.init_password", "Password")
	local f_version = ProtoField.uint16("multicraft.client.init_version", "Version", base.DEC)

	multicraft_client_commands[0x10] = {
		"INIT",                             -- Command name
		53,                                 -- Minimum message length including code
		{ f_ser_fmt,                        -- List of fields [optional]
		  f_player_name,
		  f_password,
		  f_version },
		function(buffer, pinfo, tree, t)    -- Dissector function [optional]
			t:add(f_ser_fmt, buffer(2,1))
			t:add(f_player_name, buffer(3,20))
			t:add(f_password, buffer(23,28))
			t:add(f_version, buffer(51,2))
		end
	}
end

-- TOSERVER_INIT2

multicraft_client_commands[0x11] = { "INIT2", 2 }

-- TOSERVER_GETBLOCK (obsolete)

multicraft_client_commands[0x20] = { "GETBLOCK", 2 }
multicraft_client_obsolete[0x20] = true

-- TOSERVER_ADDNODE (obsolete)

multicraft_client_commands[0x21] = { "ADDNODE", 2 }
multicraft_client_obsolete[0x21] = true

-- TOSERVER_REMOVENODE (obsolete)

multicraft_client_commands[0x22] = { "REMOVENODE", 2 }
multicraft_client_obsolete[0x22] = true

-- TOSERVER_PLAYERPOS

do
	local f_x = ProtoField.int32("multicraft.client.playerpos_x", "Position X", base.DEC)
	local f_y = ProtoField.int32("multicraft.client.playerpos_y", "Position Y", base.DEC)
	local f_z = ProtoField.int32("multicraft.client.playerpos_z", "Position Z", base.DEC)
	local f_speed_x = ProtoField.int32("multicraft.client.playerpos_speed_x", "Speed X", base.DEC)
	local f_speed_y = ProtoField.int32("multicraft.client.playerpos_speed_y", "Speed Y", base.DEC)
	local f_speed_z = ProtoField.int32("multicraft.client.playerpos_speed_z", "Speed Z", base.DEC)
	local f_pitch = ProtoField.int32("multicraft.client.playerpos_pitch", "Pitch", base.DEC)
	local f_yaw = ProtoField.int32("multicraft.client.playerpos_yaw", "Yaw", base.DEC)

	multicraft_client_commands[0x23] = {
		"PLAYERPOS", 34,
		{ f_x, f_y, f_z, f_speed_x, f_speed_y, f_speed_z, f_pitch, f_yaw },
		function(buffer, pinfo, tree, t)
			t:add(f_x, buffer(2,4))
			t:add(f_y, buffer(6,4))
			t:add(f_z, buffer(10,4))
			t:add(f_speed_x, buffer(14,4))
			t:add(f_speed_y, buffer(18,4))
			t:add(f_speed_z, buffer(22,4))
			t:add(f_pitch, buffer(26,4))
			t:add(f_yaw, buffer(30,4))
		end
	}
end

-- TOSERVER_GOTBLOCKS

do
	local f_count = ProtoField.uint8("multicraft.client.gotblocks_count", "Count", base.DEC)
	local f_block = ProtoField.bytes("multicraft.client.gotblocks_block", "Block", base.DEC)
	local f_x = ProtoField.int16("multicraft.client.gotblocks_x", "Block position X", base.DEC)
	local f_y = ProtoField.int16("multicraft.client.gotblocks_y", "Block position Y", base.DEC)
	local f_z = ProtoField.int16("multicraft.client.gotblocks_z", "Block position Z", base.DEC)

	multicraft_client_commands[0x24] = {
		"GOTBLOCKS", 3,
		{ f_count, f_block, f_x, f_y, f_z },
		function(buffer, pinfo, tree, t)
			t:add(f_count, buffer(2,1))
			local count = buffer(2,1):uint()
			if multicraft_check_length(buffer, 3 + 6*count, t) then
				pinfo.cols.info:append(" * " .. count)
				local index
				for index = 0, count - 1 do
					local pos = 3 + 6*index
					local t2 = t:add(f_block, buffer(pos, 6))
					t2:set_text("Block, X: " .. buffer(pos, 2):int()
						.. ", Y: " .. buffer(pos + 2, 2):int()
						.. ", Z: " .. buffer(pos + 4, 2):int())
					t2:add(f_x, buffer(pos, 2))
					t2:add(f_y, buffer(pos + 2, 2))
					t2:add(f_z, buffer(pos + 4, 2))
				end
			end
		end
	}
end

-- TOSERVER_DELETEDBLOCKS
-- TODO: Test this

do
	local f_count = ProtoField.uint8("multicraft.client.deletedblocks_count", "Count", base.DEC)
	local f_block = ProtoField.bytes("multicraft.client.deletedblocks_block", "Block", base.DEC)
	local f_x = ProtoField.int16("multicraft.client.deletedblocks_x", "Block position X", base.DEC)
	local f_y = ProtoField.int16("multicraft.client.deletedblocks_y", "Block position Y", base.DEC)
	local f_z = ProtoField.int16("multicraft.client.deletedblocks_z", "Block position Z", base.DEC)

	multicraft_client_commands[0x25] = {
		"DELETEDBLOCKS", 3,
		{ f_count, f_block, f_x, f_y, f_z },
		function(buffer, pinfo, tree, t)
			t:add(f_count, buffer(2,1))
			local count = buffer(2,1):uint()
			if multicraft_check_length(buffer, 3 + 6*count, t) then
				pinfo.cols.info:append(" * " .. count)
				local index
				for index = 0, count - 1 do
					local pos = 3 + 6*index
					local t2 = t:add(f_block, buffer(pos, 6))
					t2:set_text("Block, X: " .. buffer(pos, 2):int()
						.. ", Y: " .. buffer(pos + 2, 2):int()
						.. ", Z: " .. buffer(pos + 4, 2):int())
					t2:add(f_x, buffer(pos, 2))
					t2:add(f_y, buffer(pos + 2, 2))
					t2:add(f_z, buffer(pos + 4, 2))
				end
			end
		end
	}
end

-- TOSERVER_ADDNODE_FROM_INVENTORY (obsolete)

multicraft_client_commands[0x26] = { "ADDNODE_FROM_INVENTORY", 2 }
multicraft_client_obsolete[0x26] = true

-- TOSERVER_CLICK_OBJECT
-- TODO: Test this

do
	local vs_button = {
		[0] = "left",
		[1] = "right"
	}

	local f_button = ProtoField.uint8("multicraft.client.click_object_button", "Button", base.DEC, vs_button)
	local f_blockpos_x = ProtoField.int16("multicraft.client.click_object_blockpos_x", "Block position X", base.DEC)
	local f_blockpos_y = ProtoField.int16("multicraft.client.click_object_blockpos_y", "Block position Y", base.DEC)
	local f_blockpos_z = ProtoField.int16("multicraft.client.click_object_blockpos_z", "Block position Z", base.DEC)
	local f_id = ProtoField.int16("multicraft.client.click_object_id", "ID", base.DEC)
	local f_item = ProtoField.uint16("multicraft.client.click_object_item", "Item", base.DEC)

	multicraft_client_commands[0x27] = {
		"CLICK_OBJECT", 13,
		{ f_button, f_blockpos_x, f_blockpos_y, f_blockpos_z, f_id, f_item },
		function(buffer, pinfo, tree, t)
			t:add(f_button, buffer(2,1))
			t:add(f_blockpos_x, buffer(3,2))
			t:add(f_blockpos_y, buffer(5,2))
			t:add(f_blockpos_z, buffer(7,2))
			t:add(f_id, buffer(9,2))
			t:add(f_item, buffer(11,2))
		end
	}
end

-- TOSERVER_GROUND_ACTION

do
	local vs_action = {
		[0] = "Start digging",
		[1] = "Place block",
		[2] = "Stop digging",
		[3] = "Digging completed"
	}

	local f_action = ProtoField.uint8("multicraft.client.ground_action", "Action", base.DEC, vs_action)
	local f_nodepos_undersurface_x = ProtoField.int16(
		"multicraft.client.ground_action_nodepos_undersurface_x",
		"Node position (under surface) X")
	local f_nodepos_undersurface_y = ProtoField.int16(
		"multicraft.client.ground_action_nodepos_undersurface_y",
		"Node position (under surface) Y")
	local f_nodepos_undersurface_z = ProtoField.int16(
		"multicraft.client.ground_action_nodepos_undersurface_z",
		"Node position (under surface) Z")
	local f_nodepos_abovesurface_x = ProtoField.int16(
		"multicraft.client.ground_action_nodepos_abovesurface_x",
		"Node position (above surface) X")
	local f_nodepos_abovesurface_y = ProtoField.int16(
		"multicraft.client.ground_action_nodepos_abovesurface_y",
		"Node position (above surface) Y")
	local f_nodepos_abovesurface_z = ProtoField.int16(
		"multicraft.client.ground_action_nodepos_abovesurface_z",
		"Node position (above surface) Z")
	local f_item = ProtoField.uint16("multicraft.client.ground_action_item", "Item")

	multicraft_client_commands[0x28] = {
		"GROUND_ACTION", 17,
		{ f_action,
		  f_nodepos_undersurface_x,
		  f_nodepos_undersurface_y,
		  f_nodepos_undersurface_z,
		  f_nodepos_abovesurface_x,
		  f_nodepos_abovesurface_y,
		  f_nodepos_abovesurface_z,
		  f_item },
		function(buffer, pinfo, tree, t)
			t:add(f_action, buffer(2,1))
			t:add(f_nodepos_undersurface_x, buffer(3,2))
			t:add(f_nodepos_undersurface_y, buffer(5,2))
			t:add(f_nodepos_undersurface_z, buffer(7,2))
			t:add(f_nodepos_abovesurface_x, buffer(9,2))
			t:add(f_nodepos_abovesurface_y, buffer(11,2))
			t:add(f_nodepos_abovesurface_z, buffer(13,2))
			t:add(f_item, buffer(15,2))
		end
	}
end

-- TOSERVER_RELEASE (obsolete)

multicraft_client_commands[0x29] = { "RELEASE", 2 }
multicraft_client_obsolete[0x29] = true

-- TOSERVER_SIGNTEXT (old signs)
-- TODO: Test this or mark obsolete

do
	local f_blockpos_x = ProtoField.int16("multicraft.client.signtext_blockpos_x", "Block position X", base.DEC)
	local f_blockpos_y = ProtoField.int16("multicraft.client.signtext_blockpos_y", "Block position Y", base.DEC)
	local f_blockpos_z = ProtoField.int16("multicraft.client.signtext_blockpos_z", "Block position Z", base.DEC)
	local f_id = ProtoField.int16("multicraft.client.signtext_id", "ID", base.DEC)
	local f_textlen = ProtoField.uint16("multicraft.client.signtext_textlen", "Text length", base.DEC)
	local f_text = ProtoField.string("multicraft.client.signtext_text", "Text")

	multicraft_client_commands[0x30] = {
		"SIGNTEXT", 12,
		{ f_blockpos_x, f_blockpos_y, f_blockpos_z, f_id, f_textlen, f_text },
		function(buffer, pinfo, tree, t)
			t:add(f_blockpos_x, buffer(2,2))
			t:add(f_blockpos_y, buffer(4,2))
			t:add(f_blockpos_z, buffer(6,2))
			t:add(f_id, buffer(8,2))
			t:add(f_textlen, buffer(10,2))
			local textlen = buffer(10,2):uint()
			if multicraft_check_length(buffer, 12 + textlen, t) then
				t:add(f_text, buffer, buffer(12,textlen))
			end
		end
	}
end

-- TOSERVER_INVENTORY_ACTION

do
	local f_action = ProtoField.string("multicraft.client.inventory_action", "Action")

	multicraft_client_commands[0x31] = {
		"INVENTORY_ACTION", 2,
		{ f_action },
		function(buffer, pinfo, tree, t)
			t:add(f_action, buffer(2, buffer:len() - 2))
		end
	}
end

-- TOSERVER_CHAT_MESSAGE

do
	local f_length = ProtoField.uint16("multicraft.client.chat_message_length", "Length", base.DEC)
	local f_message = ProtoField.string("multicraft.client.chat_message", "Message")

	multicraft_client_commands[0x32] = {
		"CHAT_MESSAGE", 4,
		{ f_length, f_message },
		function(buffer, pinfo, tree, t)
			t:add(f_length, buffer(2,2))
			local textlen = buffer(2,2):uint()
			if multicraft_check_length(buffer, 4 + textlen*2, t) then
				t:add(f_message, multicraft_convert_utf16(buffer(4, textlen*2), "Converted chat message"))
			end
		end
	}
end

-- TOSERVER_SIGNNODETEXT

do
	local f_pos_x = ProtoField.int16("multicraft.client.signnodetext_pos_x", "Block position X", base.DEC)
	local f_pos_y = ProtoField.int16("multicraft.client.signnodetext_pos_y", "Block position Y", base.DEC)
	local f_pos_z = ProtoField.int16("multicraft.client.signnodetext_pos_z", "Block position Z", base.DEC)
	local f_textlen = ProtoField.uint16("multicraft.client.signnodetext_textlen", "Text length", base.DEC)
	local f_text = ProtoField.string("multicraft.client.signnodetext_text", "Text")

	multicraft_client_commands[0x33] = {
		"SIGNNODETEXT", 10,
		{ f_pos_x, f_pos_y, f_pos_z, f_textlen, f_text },
		function(buffer, pinfo, tree, t)
			t:add(f_pos_x, buffer(2,2))
			t:add(f_pos_y, buffer(4,2))
			t:add(f_pos_z, buffer(6,2))
			t:add(f_textlen, buffer(8,2))
			local textlen = buffer(8,2):uint()
			if multicraft_check_length(buffer, 10 + textlen, t) then
				t:add(f_text, buffer(10, textlen))
			end
		end
	}
end

-- TOSERVER_CLICK_ACTIVEOBJECT

do
	local vs_button = {
		[0] = "left",
		[1] = "right"
	}

	local f_button = ProtoField.uint8("multicraft.client.click_activeobject_button", "Button", base.DEC, vs_button)
	local f_id = ProtoField.uint16("multicraft.client.click_activeobject_id", "ID", base.DEC)
	local f_item = ProtoField.uint16("multicraft.client.click_activeobject_item", "Item", base.DEC)

	multicraft_client_commands[0x34] = {
		"CLICK_ACTIVEOBJECT", 7,
		{ f_button, f_id, f_item },
		function(buffer, pinfo, tree, t)
			t:add(f_button, buffer(2,1))
			t:add(f_id, buffer(3,2))
			t:add(f_item, buffer(5,2))
		end
	}
end

-- TOSERVER_DAMAGE

do
	local f_amount = ProtoField.uint8("multicraft.client.damage_amount", "Amount", base.DEC)

	multicraft_client_commands[0x35] = {
		"DAMAGE", 3,
		{ f_amount },
		function(buffer, pinfo, tree, t)
			t:add(f_amount, buffer(2,1))
		end
	}
end

-- TOSERVER_PASSWORD

do
	local f_old_password = ProtoField.string("multicraft.client.password_old", "Old password")
	local f_new_password = ProtoField.string("multicraft.client.password_new", "New password")

	multicraft_client_commands[0x36] = {
		"PASSWORD", 58,
		{ f_old_password, f_new_password },
		function(buffer, pinfo, tree, t)
			t:add(f_old_password, buffer(2,28))
			t:add(f_new_password, buffer(30,28))
		end
	}
end

-- TOSERVER_PLAYERITEM

do
	local f_item = ProtoField.uint16("multicraft.client.playeritem_item", "Wielded item")

	multicraft_client_commands[0x37] = {
		"PLAYERITEM", 4,
		{ f_item },
		function(buffer, pinfo, tree, t)
			t:add(f_item, buffer(2,2))
		end
	}
end

-- TOSERVER_RESPAWN

multicraft_client_commands[0x38] = { "RESPAWN", 2 }




--------------------------------------------
-- Part 2                                 --
-- Server command dissectors (TOCLIENT_*) --
--------------------------------------------

multicraft_server_commands = {}
multicraft_server_obsolete = {}

-- TOCLIENT_INIT

do
	local f_version = ProtoField.uint8("multicraft.server.init_version", "Deployed version", base.DEC)
	local f_pos_x = ProtoField.int16("multicraft.server.init_pos_x", "Position X", base.DEC)
	local f_pos_y = ProtoField.int16("multicraft.server.init_pos_y", "Position Y", base.DEC)
	local f_pos_z = ProtoField.int16("multicraft.server.init_pos_x", "Position Z", base.DEC)
	local f_map_seed = ProtoField.uint64("multicraft.server.init_map_seed", "Map seed", base.DEC)

	multicraft_server_commands[0x10] = {
		"INIT", 17,
		{ f_version, f_pos_x, f_pos_y, f_pos_z, f_map_seed },
		function(buffer, pinfo, tree, t)
			t:add(f_version, buffer(2,1))
			t:add(f_pos_x, buffer(3,2))
			t:add(f_pos_y, buffer(5,2))
			t:add(f_pos_z, buffer(7,2))
			t:add(f_map_seed, buffer(9,8))
		end
	}
end

-- TOCLIENT_BLOCKDATA

do
	local f_x = ProtoField.int16("multicraft.server.blockdata_x", "Block position X", base.DEC)
	local f_y = ProtoField.int16("multicraft.server.blockdata_y", "Block position Y", base.DEC)
	local f_z = ProtoField.int16("multicraft.server.blockdata_z", "Block position Z", base.DEC)
	local f_data = ProtoField.bytes("multicraft.server.blockdata_block", "Serialized MapBlock")

	multicraft_server_commands[0x20] = {
		"BLOCKDATA", 8,
		{ f_x, f_y, f_z, f_data },
		function(buffer, pinfo, tree, t)
			t:add(f_x, buffer(2,2))
			t:add(f_y, buffer(4,2))
			t:add(f_z, buffer(6,2))
			t:add(f_data, buffer(8, buffer:len() - 8))
		end
	}
end

-- TOCLIENT_ADDNODE

do
	local f_x = ProtoField.int16("multicraft.server.addnode_x", "Position X", base.DEC)
	local f_y = ProtoField.int16("multicraft.server.addnode_y", "Position Y", base.DEC)
	local f_z = ProtoField.int16("multicraft.server.addnode_z", "Position Z", base.DEC)
	local f_data = ProtoField.bytes("multicraft.server.addnode_node", "Serialized MapNode")

	multicraft_server_commands[0x21] = {
		"ADDNODE", 8,
		{ f_x, f_y, f_z, f_data },
		function(buffer, pinfo, tree, t)
			t:add(f_x, buffer(2,2))
			t:add(f_y, buffer(4,2))
			t:add(f_z, buffer(6,2))
			t:add(f_data, buffer(8, buffer:len() - 8))
		end
	}
end

-- TOCLIENT_REMOVENODE

do
	local f_x = ProtoField.int16("multicraft.server.removenode_x", "Position X", base.DEC)
	local f_y = ProtoField.int16("multicraft.server.removenode_y", "Position Y", base.DEC)
	local f_z = ProtoField.int16("multicraft.server.removenode_z", "Position Z", base.DEC)

	multicraft_server_commands[0x22] = {
		"REMOVENODE", 8,
		{ f_x, f_y, f_z },
		function(buffer, pinfo, tree, t)
			t:add(f_x, buffer(2,2))
			t:add(f_y, buffer(4,2))
			t:add(f_z, buffer(6,2))
		end
	}
end

-- TOCLIENT_PLAYERPOS (obsolete)

multicraft_server_commands[0x23] = { "PLAYERPOS", 2 }
multicraft_server_obsolete[0x23] = true

-- TOCLIENT_PLAYERINFO

do
	local f_count = ProtoField.uint16("multicraft.server.playerinfo_count", "Count", base.DEC)
	local f_player = ProtoField.bytes("multicraft.server.playerinfo_player", "Player", base.DEC)
	local f_peer_id = ProtoField.uint16("multicraft.server.playerinfo_peer_id", "Peer ID", base.DEC)
	local f_name = ProtoField.string("multicraft.server.playerinfo_name", "Name")

	multicraft_server_commands[0x24] = {
		"PLAYERINFO", 2,
		{ f_count, f_player, f_peer_id, f_name },
		function(buffer, pinfo, tree, t)
			local count = 0
			local pos, index
			for pos = 2, buffer:len() - 22, 22 do  -- does lua have integer division?
				count = count + 1
			end
			t:add(f_count, count):set_generated()
			t:set_len(2 + 22 * count)
			pinfo.cols.info:append(" * " .. count)
			for index = 0, count - 1 do
				local pos = 2 + 22 * index
				local t2 = t:add(f_player, buffer(pos, 22))
				t2:set_text("Player, ID: " .. buffer(pos, 2):uint()
					.. ", Name: " .. buffer(pos + 2, 20):string())
				t2:add(f_peer_id, buffer(pos, 2))
				t2:add(f_name, buffer(pos + 2, 20))
			end
		end
	}
end

-- TOCLIENT_OPT_BLOCK_NOT_FOUND (obsolete)

multicraft_server_commands[0x25] = { "OPT_BLOCK_NOT_FOUND", 2 }
multicraft_server_obsolete[0x25] = true

-- TOCLIENT_SECTORMETA (obsolete)

multicraft_server_commands[0x26] = { "SECTORMETA", 2 }
multicraft_server_obsolete[0x26] = true

-- TOCLIENT_INVENTORY

do
	local f_inventory = ProtoField.string("multicraft.server.inventory", "Inventory")

	multicraft_server_commands[0x27] = {
		"INVENTORY", 2,
		{ f_inventory },
		function(buffer, pinfo, tree, t)
			t:add(f_inventory, buffer(2, buffer:len() - 2))
		end
	}
end

-- TOCLIENT_OBJECTDATA

do
	local f_player_count = ProtoField.uint16("multicraft.server.objectdata_player_count",
		"Count of player positions", base.DEC)
	local f_player = ProtoField.bytes("multicraft.server.objectdata_player", "Player position")
	local f_peer_id = ProtoField.uint16("multicraft.server.objectdata_player_peer_id", "Peer ID")
	local f_x = ProtoField.int32("multicraft.server.objectdata_player_x", "Position X", base.DEC)
	local f_y = ProtoField.int32("multicraft.server.objectdata_player_y", "Position Y", base.DEC)
	local f_z = ProtoField.int32("multicraft.server.objectdata_player_z", "Position Z", base.DEC)
	local f_speed_x = ProtoField.int32("multicraft.server.objectdata_player_speed_x", "Speed X", base.DEC)
	local f_speed_y = ProtoField.int32("multicraft.server.objectdata_player_speed_y", "Speed Y", base.DEC)
	local f_speed_z = ProtoField.int32("multicraft.server.objectdata_player_speed_z", "Speed Z", base.DEC)
	local f_pitch = ProtoField.int32("multicraft.server.objectdata_player_pitch", "Pitch", base.DEC)
	local f_yaw = ProtoField.int32("multicraft.server.objectdata_player_yaw", "Yaw", base.DEC)
	local f_block_count = ProtoField.uint16("multicraft.server.objectdata_block_count",
		"Count of blocks", base.DEC)

	multicraft_server_commands[0x28] = {
		"OBJECTDATA", 6,
		{ f_player_count, f_player, f_peer_id, f_x, f_y, f_z,
		  f_speed_x, f_speed_y, f_speed_z,f_pitch, f_yaw,
		  f_block_count },
		function(buffer, pinfo, tree, t)
			local t2, index, pos

			local player_count_pos = 2
			local player_count = buffer(player_count_pos, 2):uint()
			t:add(f_player_count, buffer(player_count_pos, 2))

			local block_count_pos = player_count_pos + 2 + 34 * player_count
			if not multicraft_check_length(buffer, block_count_pos + 2, t) then
				return
			end

			for index = 0, player_count - 1 do
				pos = player_count_pos + 2 + 34 * index
				t2 = t:add(f_player, buffer(pos, 34))
				t2:set_text("Player position, ID: " .. buffer(pos, 2):uint())
				t2:add(f_peer_id, buffer(pos, 2))
				t2:add(f_x, buffer(pos + 2, 4))
				t2:add(f_y, buffer(pos + 6, 4))
				t2:add(f_z, buffer(pos + 10, 4))
				t2:add(f_speed_x, buffer(pos + 14, 4))
				t2:add(f_speed_y, buffer(pos + 18, 4))
				t2:add(f_speed_z, buffer(pos + 22, 4))
				t2:add(f_pitch, buffer(pos + 26, 4))
				t2:add(f_yaw, buffer(pos + 30, 4))
			end

			local block_count = buffer(block_count_pos, 2):uint()
			t:add(f_block_count, buffer(block_count_pos, 2))

			-- TODO: dissect blocks.
			-- NOTE: block_count > 0 is obsolete. (?)

			pinfo.cols.info:append(" * " .. (player_count + block_count))
		end
	}
end

-- TOCLIENT_TIME_OF_DAY

do
	local f_time = ProtoField.uint16("multicraft.server.time_of_day", "Time", base.DEC)

	multicraft_server_commands[0x29] = {
		"TIME_OF_DAY", 4,
		{ f_time },
		function(buffer, pinfo, tree, t)
			t:add(f_time, buffer(2,2))
		end
	}
end

-- TOCLIENT_CHAT_MESSAGE

do
	local f_length = ProtoField.uint16("multicraft.server.chat_message_length", "Length", base.DEC)
	local f_message = ProtoField.string("multicraft.server.chat_message", "Message")

	multicraft_server_commands[0x30] = {
		"CHAT_MESSAGE", 4,
		{ f_length, f_message },
		function(buffer, pinfo, tree, t)
			t:add(f_length, buffer(2,2))
			local textlen = buffer(2,2):uint()
			if multicraft_check_length(buffer, 4 + textlen*2, t) then
				t:add(f_message, multicraft_convert_utf16(buffer(4, textlen*2), "Converted chat message"))
			end
		end
	}
end

-- TOCLIENT_ACTIVE_OBJECT_REMOVE_ADD

do
	local f_removed_count = ProtoField.uint16(
		"multicraft.server.active_object_remove_add_removed_count",
		"Count of removed objects", base.DEC)
	local f_removed = ProtoField.bytes(
		"multicraft.server.active_object_remove_add_removed",
		"Removed object")
	local f_removed_id = ProtoField.uint16(
		"multicraft.server.active_object_remove_add_removed_id",
		"ID", base.DEC)

	local f_added_count = ProtoField.uint16(
		"multicraft.server.active_object_remove_add_added_count",
		"Count of added objects", base.DEC)
	local f_added = ProtoField.bytes(
		"multicraft.server.active_object_remove_add_added",
		"Added object")
	local f_added_id = ProtoField.uint16(
		"multicraft.server.active_object_remove_add_added_id",
		"ID", base.DEC)
	local f_added_type = ProtoField.uint8(
		"multicraft.server.active_object_remove_add_added_type",
		"Type", base.DEC)
	local f_added_init_length = ProtoField.uint32(
		"multicraft.server.active_object_remove_add_added_init_length",
		"Initialization data length", base.DEC)
	local f_added_init_data = ProtoField.bytes(
		"multicraft.server.active_object_remove_add_added_init_data",
		"Initialization data")

	multicraft_server_commands[0x31] = {
		"ACTIVE_OBJECT_REMOVE_ADD", 6,
		{ f_removed_count, f_removed, f_removed_id,
		  f_added_count, f_added, f_added_id,
		  f_added_type, f_added_init_length, f_added_init_data },
		function(buffer, pinfo, tree, t)
			local t2, index, pos

			local removed_count_pos = 2
			local removed_count = buffer(removed_count_pos, 2):uint()
			t:add(f_removed_count, buffer(removed_count_pos, 2))

			local added_count_pos = removed_count_pos + 2 + 2 * removed_count
			if not multicraft_check_length(buffer, added_count_pos + 2, t) then
				return
			end

			-- Loop through removed active objects
			for index = 0, removed_count - 1 do
				pos = removed_count_pos + 2 + 2 * index
				t2 = t:add(f_removed, buffer(pos, 2))
				t2:set_text("Removed object, ID = " ..  buffer(pos, 2):uint())
				t2:add(f_removed_id, buffer(pos, 2))
			end

			local added_count = buffer(added_count_pos, 2):uint()
			t:add(f_added_count, buffer(added_count_pos, 2))

			-- Loop through added active objects
			pos = added_count_pos + 2
			for index = 0, added_count - 1 do
				if not multicraft_check_length(buffer, pos + 7, t) then
					return
				end

				local init_length = buffer(pos + 3, 4):uint()
				if not multicraft_check_length(buffer, pos + 7 + init_length, t) then
					return
				end

				t2 = t:add(f_added, buffer(pos, 7 + init_length))
				t2:set_text("Added object, ID = " .. buffer(pos, 2):uint())
				t2:add(f_added_id, buffer(pos, 2))
				t2:add(f_added_type, buffer(pos + 2, 1))
				t2:add(f_added_init_length, buffer(pos + 3, 4))
				t2:add(f_added_init_data, buffer(pos + 7, init_length))

				pos = pos + 7 + init_length
			end

			pinfo.cols.info:append(" * " .. (removed_count + added_count))
		end
	}
end

-- TOCLIENT_ACTIVE_OBJECT_MESSAGES

do
	local f_object_count = ProtoField.uint16(
		"multicraft.server.active_object_messages_object_count",
		"Count of objects", base.DEC)
	local f_object = ProtoField.bytes(
		"multicraft.server.active_object_messages_object",
		"Object")
	local f_object_id = ProtoField.uint16(
		"multicraft.server.active_object_messages_id",
		"ID", base.DEC)
	local f_message_length = ProtoField.uint16(
		"multicraft.server.active_object_messages_message_length",
		"Message length", base.DEC)
	local f_message = ProtoField.bytes(
		"multicraft.server.active_object_messages_message",
		"Message")

	multicraft_server_commands[0x32] = {
		"ACTIVE_OBJECT_MESSAGES", 2,
		{ f_object_count, f_object, f_object_id, f_message_length, f_message },
		function(buffer, pinfo, tree, t)
			local t2, count, pos, message_length

			count = 0
			pos = 2
			while pos < buffer:len() do
				if not multicraft_check_length(buffer, pos + 4, t) then
					return
				end
				message_length = buffer(pos + 2, 2):uint()
				if not multicraft_check_length(buffer, pos + 4 + message_length, t) then
					return
				end
				count = count + 1
				pos = pos + 4 + message_length
			end

			pinfo.cols.info:append(" * " .. count)
			t:add(f_object_count, count):set_generated()

			pos = 2
			while pos < buffer:len() do
				message_length = buffer(pos + 2, 2):uint()

				t2 = t:add(f_object, buffer(pos, 4 + message_length))
				t2:set_text("Object, ID = " ..  buffer(pos, 2):uint())
				t2:add(f_object_id, buffer(pos, 2))
				t2:add(f_message_length, buffer(pos + 2, 2))
				t2:add(f_message, buffer(pos + 4, message_length))

				pos = pos + 4 + message_length
			end
		end
	}
end

-- TOCLIENT_HP

do
	local f_hp = ProtoField.uint8("multicraft.server.hp", "Hitpoints", base.DEC)

	multicraft_server_commands[0x33] = {
		"HP", 3,
		{ f_hp },
		function(buffer, pinfo, tree, t)
			t:add(f_hp, buffer(2,1))
		end
	}
end

-- TOCLIENT_MOVE_PLAYER

do
	local f_x = ProtoField.int32("multicraft.server.move_player_x", "Position X", base.DEC)
	local f_y = ProtoField.int32("multicraft.server.move_player_y", "Position Y", base.DEC)
	local f_z = ProtoField.int32("multicraft.server.move_player_z", "Position Z", base.DEC)
	local f_pitch = ProtoField.int32("multicraft.server.move_player_pitch", "Pitch", base.DEC)
	local f_yaw = ProtoField.int32("multicraft.server.move_player_yaw", "Yaw", base.DEC)
	local f_garbage = ProtoField.bytes("multicraft.server.move_player_garbage", "Garbage")

	multicraft_server_commands[0x34] = {
		"MOVE_PLAYER", 18,  -- actually 22, but see below
		{ f_x, f_y, f_z, f_pitch, f_yaw, f_garbage },
		function(buffer, pinfo, tree, t)
			t:add(f_x, buffer(2, 4))
			t:add(f_y, buffer(6, 4))
			t:add(f_z, buffer(10, 4))

			-- Compatibility note:
			-- Up to 2011-08-23, there was a bug in MultiCraft that
			-- caused the server to serialize the pitch and yaw
			-- with 2 bytes each instead of 4, creating a
			-- malformed message.
			if buffer:len() >= 22 then
				t:add(f_pitch, buffer(14, 4))
				t:add(f_yaw, buffer(18, 4))
			else
				t:add(f_garbage, buffer(14, 4))
				t:add_expert_info(PI_MALFORMED, PI_WARN, "Malformed pitch and yaw, possibly caused by a serialization bug in MultiCraft")
			end
		end
	}
end

-- TOCLIENT_ACCESS_DENIED

do
	local f_reason_length = ProtoField.uint16("multicraft.server.access_denied_reason_length", "Reason length", base.DEC)
	local f_reason = ProtoField.string("multicraft.server.access_denied_reason", "Reason")

	multicraft_server_commands[0x35] = {
		"ACCESS_DENIED", 4,
		{ f_reason_length, f_reason },
		function(buffer, pinfo, tree, t)
			t:add(f_reason_length, buffer(2,2))
			local reason_length = buffer(2,2):uint()
			if multicraft_check_length(buffer, 4 + reason_length * 2, t) then
				t:add(f_reason, multicraft_convert_utf16(buffer(4, reason_length * 2), "Converted reason message"))
			end
		end
	}
end

-- TOCLIENT_PLAYERITEM

do
	local f_count = ProtoField.uint16(
		"multicraft.server.playeritem_count",
		"Count of players", base.DEC)
	local f_player = ProtoField.bytes(
		"multicraft.server.playeritem_player",
		"Player")
	local f_peer_id = ProtoField.uint16(
		"multicraft.server.playeritem_peer_id",
		"Peer ID", base.DEC)
	local f_item_length = ProtoField.uint16(
		"multicraft.server.playeritem_item_length",
		"Item information length", base.DEC)
	local f_item = ProtoField.string(
		"multicraft.server.playeritem_item",
		"Item information")

	multicraft_server_commands[0x36] = {
		"PLAYERITEM", 4,
		{ f_count, f_player, f_peer_id, f_item_length, f_item },
		function(buffer, pinfo, tree, t)
			local count, index, pos, item_length

			count = buffer(2,2):uint()
			pinfo.cols.info:append(" * " .. count)
			t:add(f_count, buffer(2,2))

			pos = 4
			for index = 0, count - 1 do
				if not multicraft_check_length(buffer, pos + 4, t) then
					return
				end
				item_length = buffer(pos + 2, 2):uint()
				if not multicraft_check_length(buffer, pos + 4 + item_length, t) then
					return
				end

				local t2 = t:add(f_player, buffer(pos, 4 + item_length))
				t2:set_text("Player, ID: " .. buffer(pos, 2):uint())
				t2:add(f_peer_id, buffer(pos, 2))
				t2:add(f_item_length, buffer(pos + 2, 2))
				t2:add(f_item, buffer(pos + 4, item_length))

				pos = pos + 4 + item_length
			end
		end
	}
end

-- TOCLIENT_DEATHSCREEN

do
	local vs_set_camera_point_target = {
		[0] = "False",
		[1] = "True"
	}

	local f_set_camera_point_target = ProtoField.uint8(
		"multicraft.server.deathscreen_set_camera_point_target",
		"Set camera point target", base.DEC, vs_set_camera_point_target)
	local f_camera_point_target_x = ProtoField.int32(
		"multicraft.server.deathscreen_camera_point_target_x",
		"Camera point target X", base.DEC)
	local f_camera_point_target_y = ProtoField.int32(
		"multicraft.server.deathscreen_camera_point_target_y",
		"Camera point target Y", base.DEC)
	local f_camera_point_target_z = ProtoField.int32(
		"multicraft.server.deathscreen_camera_point_target_z",
		"Camera point target Z", base.DEC)

	multicraft_server_commands[0x37] = {
		"DEATHSCREEN", 15,
		{ f_set_camera_point_target, f_camera_point_target_x,
		  f_camera_point_target_y, f_camera_point_target_z},
		function(buffer, pinfo, tree, t)
			t:add(f_set_camera_point_target, buffer(2,1))
			t:add(f_camera_point_target_x, buffer(3,4))
			t:add(f_camera_point_target_y, buffer(7,4))
			t:add(f_camera_point_target_z, buffer(11,4))
		end
	}
end




------------------------------------
-- Part 3                         --
-- Wrapper protocol subdissectors --
------------------------------------

-- multicraft.control dissector

do
	local p_control = Proto("multicraft.control", "MultiCraft Control")

	local vs_control_type = {
		[0] = "Ack",
		[1] = "Set Peer ID",
		[2] = "Ping",
		[3] = "Disco"
	}

	local f_control_type = ProtoField.uint8("multicraft.control.type", "Control Type", base.DEC, vs_control_type)
	local f_control_ack = ProtoField.uint16("multicraft.control.ack", "ACK sequence number", base.DEC)
	local f_control_peerid = ProtoField.uint8("multicraft.control.peerid", "New peer ID", base.DEC)
	p_control.fields = { f_control_type, f_control_ack, f_control_peerid }

	local data_dissector = Dissector.get("data")

	function p_control.dissector(buffer, pinfo, tree)
		local t = tree:add(p_control, buffer(0,1))
		t:add(f_control_type, buffer(0,1))

		pinfo.cols.info = "Control message"

		local pos = 1
		if buffer(0,1):uint() == 0 then
			pos = 3
			t:set_len(3)
			t:add(f_control_ack, buffer(1,2))
			pinfo.cols.info = "Ack " .. buffer(1,2):uint()
		elseif buffer(0,1):uint() == 1 then
			pos = 3
			t:set_len(3)
			t:add(f_control_peerid, buffer(1,2))
			pinfo.cols.info = "Set peer ID " .. buffer(1,2):uint()
		elseif buffer(0,1):uint() == 2 then
			pinfo.cols.info = "Ping"
		elseif buffer(0,1):uint() == 3 then
			pinfo.cols.info = "Disco"
		end

		data_dissector:call(buffer(pos):tvb(), pinfo, tree)
	end
end

-- multicraft.client dissector
-- multicraft.server dissector

-- Defines the multicraft.client or multicraft.server Proto. These two protocols
-- are created by the same function because they are so similar.
-- Parameter: proto: the Proto object
-- Parameter: this_peer: "Client" or "Server"
-- Parameter: other_peer: "Server" or "Client"
-- Parameter: commands: table of command information, built above
-- Parameter: obsolete: table of obsolete commands, built above
function multicraft_define_client_or_server_proto(is_client)
	-- Differences between multicraft.client and multicraft.server
	local proto_name, this_peer, other_peer, empty_message_info
	local commands, obsolete
	if is_client then
		proto_name = "multicraft.client"
		this_peer = "Client"
		other_peer = "Server"
		empty_message_info = "Empty message / Connect"
		commands = multicraft_client_commands  -- defined in Part 1
		obsolete = multicraft_client_obsolete  -- defined in Part 1
	else
		proto_name = "multicraft.server"
		this_peer = "Server"
		other_peer = "Client"
		empty_message_info = "Empty message"
		commands = multicraft_server_commands  -- defined in Part 2
		obsolete = multicraft_server_obsolete  -- defined in Part 2
	end

	-- Create the protocol object.
	local proto = Proto(proto_name, "MultiCraft " .. this_peer .. " to " .. other_peer)

	-- Create a table vs_command that maps command codes to command names.
	local vs_command = {}
	local code, command_info
	for code, command_info in pairs(commands) do
		local command_name = command_info[1]
		vs_command[code] = "TO" .. other_peer:upper() .. "_" .. command_name
	end

	-- Field definitions
	local f_command = ProtoField.uint16(proto_name .. ".command", "Command", base.HEX, vs_command)
	local f_empty = ProtoField.bool(proto_name .. ".empty", "Is empty", BASE_NONE)
	proto.fields = { f_command, f_empty }

	-- Add command-specific fields to the protocol
	for code, command_info in pairs(commands) do
		local command_fields = command_info[3]
		if command_fields ~= nil then
			local index, field
			for index, field in ipairs(command_fields) do
				table.insert(proto.fields, field)
			end
		end
	end

	-- multicraft.client or multicraft.server dissector function
	function proto.dissector(buffer, pinfo, tree)
		local t = tree:add(proto, buffer)

		pinfo.cols.info = this_peer

		if buffer:len() == 0 then
			-- Empty message.
			t:add(f_empty, 1):set_generated()
			pinfo.cols.info:append(": " .. empty_message_info)

		elseif multicraft_check_length(buffer, 2, t) then
			-- Get the command code.
			t:add(f_command, buffer(0,2))
			local code = buffer(0,2):uint()
			local command_info = commands[code]
			if command_info == nil then
				-- Error: Unknown command.
				pinfo.cols.info:append(": Unknown command")
				t:add_expert_info(PI_UNDECODED, PI_WARN, "Unknown " .. this_peer .. " to " .. other_peer .. " command")
			else
				-- Process a known command
				local command_name = command_info[1]
				local command_min_length = command_info[2]
				local command_fields = command_info[3]
				local command_dissector = command_info[4]
				if multicraft_check_length(buffer, command_min_length, t) then
					pinfo.cols.info:append(": " .. command_name)
					if command_dissector ~= nil then
						command_dissector(buffer, pinfo, tree, t)
					end
				end
				if obsolete[code] then
					t:add_expert_info(PI_REQUEST_CODE, PI_WARN, "Obsolete command.")
				end
			end
		end
	end
end

multicraft_define_client_or_server_proto(true)  -- multicraft.client
multicraft_define_client_or_server_proto(false) -- multicraft.server

-- multicraft.split dissector

do
	local p_split = Proto("multicraft.split", "MultiCraft Split Message")

	local f_split_seq = ProtoField.uint16("multicraft.split.seq", "Sequence number", base.DEC)
	local f_split_chunkcount = ProtoField.uint16("multicraft.split.chunkcount", "Chunk count", base.DEC)
	local f_split_chunknum = ProtoField.uint16("multicraft.split.chunknum", "Chunk number", base.DEC)
	local f_split_data = ProtoField.bytes("multicraft.split.data", "Split message data")
	p_split.fields = { f_split_seq, f_split_chunkcount, f_split_chunknum, f_split_data }

	function p_split.dissector(buffer, pinfo, tree)
		local t = tree:add(p_split, buffer(0,6))
		t:add(f_split_seq, buffer(0,2))
		t:add(f_split_chunkcount, buffer(2,2))
		t:add(f_split_chunknum, buffer(4,2))
		t:add(f_split_data, buffer(6))
		pinfo.cols.info:append(" " .. buffer(0,2):uint() .. " chunk " .. buffer(4,2):uint() .. "/" .. buffer(2,2):uint())
	end
end




-------------------------------------
-- Part 4                          --
-- Wrapper protocol main dissector --
-------------------------------------

-- multicraft dissector

do
	local p_multicraft = Proto("multicraft", "MultiCraft")

	local multicraft_id = 0x4f457403
	local vs_id = {
		[multicraft_id] = "Valid"
	}

	local vs_peer = {
		[0] = "Inexistent",
		[1] = "Server"
	}

	local vs_type = {
		[0] = "Control",
		[1] = "Original",
		[2] = "Split",
		[3] = "Reliable"
	}

	local f_id = ProtoField.uint32("multicraft.id", "ID", base.HEX, vs_id)
	local f_peer = ProtoField.uint16("multicraft.peer", "Peer", base.DEC, vs_peer)
	local f_channel = ProtoField.uint8("multicraft.channel", "Channel", base.DEC)
	local f_type = ProtoField.uint8("multicraft.type", "Type", base.DEC, vs_type)
	local f_seq = ProtoField.uint16("multicraft.seq", "Sequence number", base.DEC)
	local f_subtype = ProtoField.uint8("multicraft.subtype", "Subtype", base.DEC, vs_type)

	p_multicraft.fields = { f_id, f_peer, f_channel, f_type, f_seq, f_subtype }

	local data_dissector = Dissector.get("data")
	local control_dissector = Dissector.get("multicraft.control")
	local client_dissector = Dissector.get("multicraft.client")
	local server_dissector = Dissector.get("multicraft.server")
	local split_dissector = Dissector.get("multicraft.split")

	function p_multicraft.dissector(buffer, pinfo, tree)

		-- Add MultiCraft tree item and verify the ID
		local t = tree:add(p_multicraft, buffer(0,8))
		t:add(f_id, buffer(0,4))
		if buffer(0,4):uint() ~= multicraft_id then
			t:add_expert_info(PI_UNDECODED, PI_WARN, "Invalid ID, this is not a MultiCraft packet")
			return
		end

		-- ID is valid, so replace packet's shown protocol
		pinfo.cols.protocol = "MultiCraft"
		pinfo.cols.info = "MultiCraft"

		-- Set the other header fields
		t:add(f_peer, buffer(4,2))
		t:add(f_channel, buffer(6,1))
		t:add(f_type, buffer(7,1))
		t:set_text("MultiCraft, Peer: " .. buffer(4,2):uint() .. ", Channel: " .. buffer(6,1):uint())

		local reliability_info
		if buffer(7,1):uint() == 3 then
			-- Reliable message
			reliability_info = "Seq=" .. buffer(8,2):uint()
			t:set_len(11)
			t:add(f_seq, buffer(8,2))
			t:add(f_subtype, buffer(10,1))
			pos = 10
		else
			-- Unreliable message
			reliability_info = "Unrel"
			pos = 7
		end

		if buffer(pos,1):uint() == 0 then
			-- Control message, possibly reliable
			control_dissector:call(buffer(pos+1):tvb(), pinfo, tree)
		elseif buffer(pos,1):uint() == 1 then
			-- Original message, possibly reliable
			if buffer(4,2):uint() == 1 then
				server_dissector:call(buffer(pos+1):tvb(), pinfo, tree)
			else
				client_dissector:call(buffer(pos+1):tvb(), pinfo, tree)
			end
		elseif buffer(pos,1):uint() == 2 then
			-- Split message, possibly reliable
			if buffer(4,2):uint() == 1 then
				pinfo.cols.info = "Server: Split message"
			else
				pinfo.cols.info = "Client: Split message"
			end
			split_dissector:call(buffer(pos+1):tvb(), pinfo, tree)
		elseif buffer(pos,1):uint() == 3 then
			-- Doubly reliable message??
			t:add_expert_info(PI_MALFORMED, PI_ERROR, "Reliable message wrapped in reliable message")
		else
			data_dissector:call(buffer(pos+1):tvb(), pinfo, tree)
		end

		pinfo.cols.info:append(" (" .. reliability_info .. ")")

	end

	-- FIXME Is there a way to let the dissector table check if the first payload bytes are 0x4f457403?
	DissectorTable.get("udp.port"):add(30000, p_multicraft)
	DissectorTable.get("udp.port"):add(30001, p_multicraft)
end




-----------------------
-- Part 5            --
-- Utility functions --
-----------------------

-- Checks if a (sub-)Tvb is long enough to be further dissected.
-- If it is long enough, sets the dissector tree item length to min_len
-- and returns true. If it is not long enough, adds expert info to the
-- dissector tree and returns false.
-- Parameter: tvb: the Tvb
-- Parameter: min_len: required minimum length
-- Parameter: t: dissector tree item
-- Returns: true if tvb:len() >= min_len, false otherwise
function multicraft_check_length(tvb, min_len, t)
	if tvb:len() >= min_len then
		t:set_len(min_len)
		return true

	-- Tvb:reported_length_remaining() has been added in August 2011
	-- and is not yet widely available, disable for the time being
	-- TODO: uncomment at a later date
	-- TODO: when uncommenting this, also re-check if other parts of
	-- the dissector could benefit from reported_length_remaining
	--elseif tvb:reported_length_remaining() >= min_len then
	--	t:add_expert_info(PI_UNDECODED, PI_INFO, "Only part of this packet was captured, unable to decode.")
	--	return false

	else
		t:add_expert_info(PI_MALFORMED, PI_ERROR, "Message is too short")
		return false
	end
end

-- Takes a Tvb or TvbRange (i.e. part of a packet) that
-- contains a UTF-16 string and returns a TvbRange containing
-- string converted to ASCII. Any characters outside the range
-- 0x20 to 0x7e are replaced by a question mark.
-- Parameter: tvb: Tvb or TvbRange that contains the UTF-16 data
-- Parameter: name: will be the name of the newly created Tvb.
-- Returns: New TvbRange containing the ASCII string.
-- TODO: Handle surrogates (should only produce one question mark)
-- TODO: Remove this when Wireshark supports UTF-16 strings natively.
function multicraft_convert_utf16(tvb, name)
	local hex, pos, char
	hex = ""
	for pos = 0, tvb:len() - 2, 2 do
		char = tvb(pos, 2):uint()
		if (char >= 0x20) and (char <= 0x7e) then
			hex = hex .. string.format(" %02x", char)
		else
			hex = hex .. " 3F"
		end
	end
	if hex == "" then
		-- This is a hack to avoid a failed assertion in tvbuff.c
		-- (function: ensure_contiguous_no_exception)
		return ByteArray.new("00"):tvb(name):range(0,0)
	else
		return ByteArray.new(hex):tvb(name):range()
	end
end

