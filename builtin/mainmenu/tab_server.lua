--Minetest
--Copyright (C) 2014 sapier
--
--This program is free software; you can redistribute it and/or modify
--it under the terms of the GNU Lesser General Public License as published by
--the Free Software Foundation; either version 3.0 of the License, or
--(at your option) any later version.
--
--This program is distributed in the hope that it will be useful,
--but WITHOUT ANY WARRANTY; without even the implied warranty of
--MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--GNU Lesser General Public License for more details.
--
--You should have received a copy of the GNU Lesser General Public License along
--with this program; if not, write to the Free Software Foundation, Inc.,
--51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

--------------------------------------------------------------------------------
local function get_formspec(tabview, name, tabdata)

        local index = menudata.worldlist:get_current_index(
                                tonumber(multicraft.setting_get("mainmenu_last_selected_world"))
                                )

        local retval =
            "size[16,11]"..
            "box[-100,8.5;200,10;#999999]" ..
            "box[-100,-10;200,12;#999999]" ..
            "bgcolor[#00000070;true]"..
            "image_button[4,8.7;3.95,0.8;"..multicraft.formspec_escape(mm_texture.basetexturedir).."menu_button.png;start_server;".. fgettext("Play") .. ";true;true;"..multicraft.formspec_escape(mm_texture.basetexturedir).."menu_button_b.png]"..
            "image_button[7.8,8.7;3.95,0.8;"..multicraft.formspec_escape(mm_texture.basetexturedir).."menu_button.png;world_create;".. fgettext("New") .. ";true;true;"..multicraft.formspec_escape(mm_texture.basetexturedir).."menu_button_b.png]"..

            "image_button[4,9.55;3.95,0.8;"..multicraft.formspec_escape(mm_texture.basetexturedir).."menu_button.png;world_delete;".. fgettext("Delete") .. ";true;true;"..multicraft.formspec_escape(mm_texture.basetexturedir).."menu_button_b.png]"..
            --"image_button[6.53,9.55;2.68,0.8;"..multicraft.formspec_escape(mm_texture.basetexturedir).."menu_button.png;world_configure;".. fgettext("Configure") .. ";true;true;"..multicraft.formspec_escape(mm_texture.basetexturedir).."menu_button_b.png]"..
            "image_button[7.8,9.55;3.95,0.8;"..multicraft.formspec_escape(mm_texture.basetexturedir).."menu_button.png;cancel;".. fgettext("Cancel") .. ";true;true;"..multicraft.formspec_escape(mm_texture.basetexturedir).."menu_button_b.png]"..
            "label[7,1.5;" .. fgettext("Select World:") .. "]" ..

            "checkbox[12,8.70;cb_creative_mode;" .. fgettext("Creative Mode") .. ";" .. dump(multicraft.setting_getbool("creative_mode")) .. "]" ..
            --"checkbox[1000,9.20;cb_enable_damage;" .. fgettext("Enable Damage") .. ";" .. dump(multicraft.setting_getbool("enable_damage")) .. "]" ..
            "checkbox[12,9.50;cb_server_announce;" .. fgettext("Public") .. ";" .. dump(multicraft.setting_getbool("server_announce")) .. "]" ..

            "checkbox[0.2,8.35;btn_single;Local Server;true]"..

            "label[-0.25,9.15;Name]" ..
            "field[1,9.45;3,0.5;te_playername;;"

        local nm = multicraft.formspec_escape(multicraft.setting_get("name"))
        if nm=='' then
           nm='Player'
        end
        retval = retval ..
                 nm .. "]" ..
                "label[-0.25,9.8;Pass]" ..
                "pwdfield[1,10.15;3,0.5;te_passwd;]"

        local bind_addr = multicraft.setting_get("bind_address")

        if not PLATFORM=="android" and bind_addr ~= nil and bind_addr ~= "" then
                retval = retval ..
                        "field[300,0;2.25,0.5;te_serveraddr;" .. fgettext("Bind Address") .. ";" ..
                        multicraft.formspec_escape(multicraft.setting_get("bind_address")) .. "]"..
                        "field[300,1;1.25,0.5;te_serverport;" .. fgettext("Port") .. ";" ..
                        multicraft.formspec_escape(multicraft.setting_get("port")) .. "]"
        else
                retval = retval ..
                        "field[300,1;3.5,0.5;te_serverport;" .. fgettext("Server Port") .. ";" ..
                        multicraft.formspec_escape(multicraft.setting_get("port")) .. "]"
        end

        retval = retval ..
                "textlist[0,2.2;16,6.5;srv_worlds;" ..
                menu_render_worldlist() ..
                ";" .. (index or 1) .. ";true]"

        return retval
end

--------------------------------------------------------------------------------
local function main_button_handler(this, fields, name, tabdata)
    multicraft.set_clouds(false)

        local world_doubleclick = false

        if fields["btn_single"]~=nil then
           local single = create_tab_single(true)
           single:set_parent(this.parent)
           single:show()
           this:hide()
           return true
        end

        if fields["srv_worlds"] ~= nil then
                local event = multicraft.explode_textlist_event(fields["srv_worlds"])

                if event.type == "DCL" then
                        world_doubleclick = true
                end
                if event.type == "CHG" then
                        multicraft.setting_set("mainmenu_last_selected_world",
                                menudata.worldlist:get_raw_index(multicraft.get_textlist_index("srv_worlds")))
                        return true
                end
        end

        if menu_handle_key_up_down(fields,"srv_worlds","mainmenu_last_selected_world") then
                return true
        end

        if fields["cb_creative_mode"] then
                multicraft.setting_set("creative_mode", fields["cb_creative_mode"])
                local bool = fields["cb_creative_mode"]
                if bool == 'true' then
                   bool = 'false'
                else
                   bool = 'true'
                end
                multicraft.setting_set("enable_damage", bool)
                multicraft.setting_save()
                return true
        end

        if fields["cb_enable_damage"] then
                multicraft.setting_set("enable_damage", fields["cb_enable_damage"])
                return true
        end

        if fields["cb_server_announce"] then
                multicraft.setting_set("server_announce", fields["cb_server_announce"])
                return true
        end

        if fields["start_server"] ~= nil or
                world_doubleclick or
                fields["key_enter"] then
                local selected = multicraft.get_textlist_index("srv_worlds")
                if selected ~= nil then
                        gamedata.playername     = fields["te_playername"]
                        gamedata.password       = fields["te_passwd"]
                        gamedata.port           = fields["te_serverport"]
                        gamedata.address        = ""
                        gamedata.selected_world = menudata.worldlist:get_raw_index(selected)

                        multicraft.setting_set("port",gamedata.port)
                        if fields["te_serveraddr"] ~= nil then
                                multicraft.setting_set("bind_address",fields["te_serveraddr"])
                        end

                        --update last game
                        local world = menudata.worldlist:get_raw_element(gamedata.selected_world)

                        local game,index = gamemgr.find_by_gameid(world.gameid)
                        multicraft.setting_set("menu_last_game",game.id)
                        multicraft.start()
                        return true
                end
        end

        if fields["world_create"] ~= nil then
                local create_world_dlg = create_create_world_dlg(true)
                create_world_dlg:set_parent(this)
                create_world_dlg:show()
                this:hide()
                return true
        end

        if fields["world_delete"] ~= nil then
                local selected = multicraft.get_textlist_index("srv_worlds")
                if selected ~= nil and
                        selected <= menudata.worldlist:size() then
                        local world = menudata.worldlist:get_list()[selected]
                        if world ~= nil and
                                world.name ~= nil and
                                world.name ~= "" then
                                local index = menudata.worldlist:get_raw_index(selected)
                                local delete_world_dlg = create_delete_world_dlg(world.name,index)
                                delete_world_dlg:set_parent(this)
                                delete_world_dlg:show()
                                this:hide()
                        end
                end

                return true
        end

        if fields["world_configure"] ~= nil then
                local selected = multicraft.get_textlist_index("srv_worlds")
                if selected ~= nil then
                        local configdialog =
                                create_configure_world_dlg(
                                                menudata.worldlist:get_raw_index(selected))

                        if (configdialog ~= nil) then
                                configdialog:set_parent(this)
                                configdialog:show()
                                this:hide()
                        end
                end
                return true
        end

    if fields["cancel"] ~= nil then
       this:hide()
       this.parent:show()
       return true
    end

        return false
end

--------------------------------------------------------------------------------
tab_server = {
        name = "server",
        caption = fgettext("Server"),
        cbf_formspec = get_formspec,
        cbf_button_handler = main_button_handler,
        on_change = nil
        }


function create_tab_server()
                local retval = dialog_create("server",
                                                                                get_formspec,
                                                                                main_button_handler,
                                                                                nil)
        return retval
end
