local M = {}

--params: string, message from finder
--address: string, address of broadcast
--return: string
M.on_message = function (params, address)
    return 'request from finder:'..params.." "..address
end


return M