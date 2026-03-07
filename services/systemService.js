const User = require("../models/User");

let systemUser;

async function initSystemUser() {
    systemUser = await User.findOne({ username: "SYSTEM" }).populate("role");
    if (!systemUser) throw new Error("SYSTEM user not found");
}

function getSystemUser(){
    if(!systemUser) throw new Error("System user not initialized");
    return systemUser;
}

module.exports ={initSystemUser , getSystemUser};

