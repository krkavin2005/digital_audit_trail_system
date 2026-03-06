const { timeStamp } = require("console");
const fs = require("fs")
const path = require("path");
const anchorPath = path.join(__dirname ,"../audit-anchor.json");

function updateAuditAnchor(hash , eventCount){
    const anchor ={
        lastHash : hash,
        eventCount,
        timestamp : new Date()
    };
    fs.writeFileSync(anchorPath , JSON.stringify(anchor , null , 2));
}

module.exports = updateAuditAnchor;