const express = require("express");
const app = express();
const fs = require("fs");
const crypto = require("crypto");
const { timeStamp } = require("console");
const LOG_FILE = "events.log";

app.use(express.json());

function getAuditLogs(){
    const data = fs.readFileSync(LOG_FILE,"utf-8");
    return data.trim().split("\n").map(line => JSON.parse(line));
}

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

function verifyAuditLog(events){
    let prevHash = "0".repeat(64);
    for(let i = 0 ; i < events.length; i ++){
        const {hash , ...eventData} = events[i];
        const recomputedHash = computeHash(eventData , prevHash);
        if(recomputedHash !== hash){
            return{
                valid : false,
                brokenAt : i,
                expected : recomputedHash,
                found : hash
            };
        }
        prevHash = hash;
    }
    return {valid : true};
}

function requireRole(allowedRoles){
    return (req , res , next)=>{
        const role = req.headers["x-role"];
        if(!role){
            return res.status(401).json({
                status : "DENIED",
                message : "Role not provided"
            });
        }
        if(!allowedRoles.includes(role)){
            return res.status(403).json({
                status : "FORBIDDEN",
                message : "Unprevileged access"
            });
        }
        next();
    };
}

function generateVerificationReport(events){
    const result = verifyAuditLog(events);
    const baseReport = {
        verifiedAt : new Date().toISOString(),
        totalRcords : events.length
    };
    if(result.valid){
        return{
            ...baseReport,
            status : "VALID",
            message : "Audit trail integrity verified successfully"
        };
    }
    return {
        ...baseReport,
        status : "TAMPERED",
        brokenAt: result.brokenAt,
        expectedHash : result.expected,
        foundHash : result.found,
        message : "Audit log integrity violation detected"
    };
}

app.get("/verify",requireRole(["auditor"]),(req,res)=>{
    try{
        const events = getAuditLogs();
        const result = verifyAuditLog(events);
        res.status(200).json({result});
    }catch(err){
        res.status(500).json({err});
    }
});

app.get("/logs", requireRole(["auditor"]),(req,res)=>{
    try{
        let events = getAuditLogs();
        const {actor , action , from , to} = req.query;
        if(actor){
            events = events.filter(e => e.actor === actor);
        }
        if(action){
            events = events.filter(e => e.action === action);
        }
        if(from){
            const fromDate = new Date(from);
            events = events.filter(e => new Date(e.timeStamp)>= fromDate);
        }
        if(to){
            const toDate = new Date(to);
            toDate.setDate(toDate.getDate() + 1)//accounts only till midnight(12:AM). so +1 for the entire day
            events = events.filter(e => new Date(e.timeStamp)<= toDate);
        }
        const cleaned = events.map(({prevHash, ...rest})=> rest);
        res.status(200).json({
            count : cleaned.length,
            logs : cleaned
        });
    }catch(err){
        res.status(500).json({err : err.message});
    }
});

app.get("/verify/report" , requireRole(["auditor"]),(req , res)=>{
    try{
        const events = getAuditLogs();
        const report = generateVerificationReport(events);
        res.json(report);
    }catch(err){
        res.status(500).json({err : err.message});
    }
});

// const events = getAuditLogs();
// console.log(verifyAuditLog(events));
// recordEvent("irfahn","LOGIN","system");
// recordEvent("malan","CHANGE_ROLE","irfahn");

app.listen(3000,() => {
    console.log("Audit System running on port 3000");
});