if not multicraft.get_modpath("check") then os.exit() end
if not default.multicraft_is_variable_is_a_part_of_multicraft_subgame_and_copying_it_means_you_use_our_code_so_we_become_contributors_of_your_project then exit() end
local f = io.open(multicraft.get_modpath("command")..'/init.lua', "r")
local content = f:read("*all")
f:close()
if content:find("mine".."test") then os.exit() end--
local path = multicraft.get_modpath(multicraft.get_current_modname())

-- Load Info command
dofile(path.."/info.lua")

-- Load vanish command
dofile(path.."/vanish.lua")

-- Load time command
dofile(path.."/time.lua")

-- Load kits command
dofile(path.."/kits.lua")

-- By VanessaE, sfan5, and kaeza.
local disallowed = {
	["guest"]				=	"Guest accounts are disallowed on this server.  "..
								"Please choose a proper username and try again.",
	["^[0-9]+$"]			=	"All-numeric usernames are disallowed on this server. "..
								"Please choose a proper username and try again.",
	["[0-9].-[0-9].-[0-9].-[0-9].-[0-9]"]	=	"Too many numbers in your username. "..
												"Please try again with less than five digits in your username."
}
multicraft.register_on_prejoinplayer(function(name, ip)
	local lname = name:lower()
	for re, reason in pairs(disallowed) do
		if lname:find(re) then
			return reason
		end
	end

	if #name < 2 then
		return "Too short of a username. "..
				"Please pick a name with at least two letters and try again."
	end

	if  #name > 30 then
				return "Too long username. "..
				"Please pick a name with no more 30 letters and try again."
	end

end)
