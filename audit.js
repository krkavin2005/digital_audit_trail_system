const fs = require("fs");
const crypto = require("crypto");
const { timeStamp } = require("console");

const LOG_FILE = "events.log";

function computeHash(eventData , prevHash){
    const payload = JSON.stringify(eventData);
    return crypto.createHash("sha256").update(payload + prevHash).digest("hex");
}

function getPreviousHash(){
    try{
        const lines = fs.readFileSync(LOG_FILE, "utf8").trim().split("\n");
        const lastEvent = JSON.parse(lines[lines.length - 1]);
        return lastEvent.hash;
    }catch{
        return "0".repeat(64);
    }
}

function recordEvent(actor , action , target){
    const prevHash = getPreviousHash();
    const event = {
        actor,
        action,
        target,
        timeStamp: Date.now(),
        prevHash
    };
    event.hash = computeHash(event , prevHash);
    fs.appendFileSync(LOG_FILE , JSON.stringify(event) + "\n");
    console.log("Recorded:", event.hash);
}

recordEvent("kavin","LOGIN","system");
recordEvent("jaivant","CHANGE_ROLE","kavin");