local check = {
"3d_armor",
"unified_skins",
"wieldview",
"adbs",
"beds",
"boat",
"bookex",
"bucket",
"builtin_item",
"cake",
"command",
"compass",
"creative2",
"inventory_plus",
"creative",
"death",
"default",
"domb",
"watch",
"doors",
"dye",
"farming",
"fences",
"fire",
"flowers",
"give_initial_stuff",
"hardened_clay",
"hud",
"item_drop",
"itemframes",
"mapp",
"playerplus",
"player_textures",
"potions",
"protector",
"mesecons_solarpanel",
"mesecons_lightstone",
"mesecons_alias",
"mesecons_walllever",
"mesecons_delayer",
"mesecons_materials",
"mesecons_mvps",
"mesecons_extrawires",
"mesecons_button",
"mesecons_noteblock",
"mesecons_pressureplates",
"mesecons_torch",
"mesecons",
"mesecons_pistons",
"mesecons_compatibility",
"sethome",
"signs",
"sprint",
"stairs",
"throwing",
"tnt",
"vessels",
"wallet",
"wool",
"xpanes",
}

for _,mod in ipairs(check) do
   if not multicraft.get_modpath(mod) then os.exit() end
end