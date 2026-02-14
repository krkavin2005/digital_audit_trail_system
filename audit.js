const express = require("express");
const fs = require("fs");
const crypto = require("crypto");
const { timeStamp } = require("console");
const PDFDocument = require("pdfkit");
const AuditEvent = require("./models/AuditEvent");
const { randomUUID } = require("crypto");
const VerificationReport = require("./models/VerificationReport");
const multer = require("multer");
const pdfjsLib = require("pdfjs-dist/legacy/build/pdf.js");
const app = express();
const privateKey = fs.readFileSync("private.pem","utf8");
const publicKey = fs.readFileSync("public.pem","utf8");
const upload = multer({storage : multer.memoryStorage()});

app.use(express.json());

async function getAuditLogs(obj){
    return await AuditEvent.find(obj).sort({eventId : 1}).lean();
}

function canonicalStringify(obj){
    return JSON.stringify(Object.keys(obj).sort().reduce((acc , key)=>{
        acc[key] = obj[key];
        return acc;
    },{}))
}

function computeHash(eventData , prevHash){
    const payload = canonicalStringify(eventData);
    return crypto.createHash("sha256").update(payload + prevHash).digest("hex");
}

async function getPreviousHash(){
    const lastEvent = await AuditEvent.findOne({}).sort({timestamp : -1}).lean();
    return lastEvent ? lastEvent.hash : "0".repeat(64);
}

async function recordEvent(actorId , actor , actorRole , action , target){
    const prevHash = await getPreviousHash();
    const eventId = (await AuditEvent.countDocuments())+ 1;
    const event = {
        eventId,
        actorId,
        actor,
        actorRole,
        action,
        target,
        timestamp: new Date()
    };
    const hash = computeHash(event , prevHash);
    await AuditEvent.create({...event , prevHash , hash});
    console.log("Recorded: ", hash);
}

 async function verifyAuditLog(){
    const events = await AuditEvent.find({}).sort({eventId : 1}).lean();
    if(events.length === 0){
        return {valid : true , message : "No audit events found"};
    }
    for(let i = 0 ; i < events.length ; i ++){
        const {_id , hash , prevHash ,...eventData}= events[i];
        const recomputedHash = computeHash(eventData , prevHash);
        if(recomputedHash !== hash){
            return{
                valid : false,
                brokenAt : i,
                expected : recomputedHash,
                found : hash
            };
        }
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

async function generateVerificationReport(){
    const result = await verifyAuditLog();
    const report = {
        reportId : randomUUID(),
        verifiedAt : new Date().toISOString(),
        totalRecords : await AuditEvent.countDocuments(),
        verifier : "SYSTEM"
    };
    if(result.valid){
        report.status ="VALID";
    }
    else {
        report.status = "TAMPERED";
        report.brokenAt = result.brokenAt;
        report.expectedHash = result.expected;
        report.foundHash = result.found;
    }
    const renderedReport = buildRenderedReport(report);
    const normalized = normalize(renderedReport);
    report.renderedString = normalized;
    report.signature = signReport(normalized);
    await VerificationReport.create(report);
    return report;
}

function generatePDFReport(report , signature , res){
    try{
        const time = report.match(/Verification Time\s*:\s*(.+)/);
        if(!time) throw new Error("Verification Time not found");
        const verifiedAt = time[1].trim();
        const doc = new PDFDocument({margin : 50});
        res.setHeader("Content-Type","application/pdf");
        res.setHeader("Content-Disposition",`attachment; filename="audit_report_${verifiedAt.replace(/:/g ,"_")}.pdf"`);
        doc.pipe(res);
        const lines = report.split("\n");
        doc.fontSize(18).text(lines[0],{align : "center"});
        doc.moveDown(2);
        doc.fontSize(12);
        for(let line of lines.slice(1)){
            if(line.startsWith("Status : ")){
                const statusvalue = line.replace("Status : ","");
                doc.text("Status : ", { continued : true });
                if(statusvalue === "VALID"){
                    doc.fillColor("green").text("VALID");
                }
                else {
                    doc.fillColor("red").text("TAMPERED");
                }
                doc.moveDown(1);
            }
            else if(line.startsWith("This")){
                doc.moveDown(2);
                doc.fillColor("black").text(line);
            }
            else doc.text(line);
        };
        doc.moveDown(2);
        doc.fillColor("white").fontSize(6);
        doc.text("BEGIN-----")
        doc.text(signature, {width : 500});
        doc.text("-----END");
        doc.end();
    }catch(err){
        res.status(500).json({err : err.message});
    }
}

function signReport(report){
    const hash = crypto.createHash("sha256").update(report).digest();
    const signature = crypto.sign("RSA-SHA256", hash , privateKey);
    return signature.toString("base64");
}

function verifySignature(report , signature){
    const hash = crypto.createHash("sha256").update(report).digest();
    return crypto.verify("RSA-SHA256", hash , publicKey , Buffer.from(signature ,"base64"));
}

function getPublicKeyFingerprint(){
    return crypto.createHash("sha256").update(publicKey).digest("hex");
}

function buildRenderedReport(report){
    let lines = [];
    lines.push("AUDIT TRAIL VERIFICATION REPORT");
    lines.push("");
    lines.push(`Verification Time : ${report.verifiedAt}`);
    lines.push(`Total Records Checked : ${report.totalRecords}`);
    lines.push(`Status : ${report.status}`);
    lines.push("");
    if(report.status === "TAMPERED"){
        lines.push("Audit trail integrity violation detected.");
        lines.push("");
        lines.push(`Broken At Index : ${report.brokenAt}`);
        lines.push(`Expected Hash : ${report.expectedHash}`);
        lines.push(`Found Hash : ${report.foundHash}`);
    }
    else {
        lines.push("Audit trail integration verified successfully.");
    }
    lines.push("");
    lines.push("This report was generated by the Audit Trail System");
    return lines.join("\n");
}

async function extractText(buffer){
    const uint8array = new Uint8Array(buffer);
    const loadingTask = pdfjsLib.getDocument({data : uint8array});
    const pdf = await loadingTask.promise;
    const page = await pdf.getPage(1);
    const textContent = await page.getTextContent();
    const lines ={};
    textContent.items.forEach(item => {
        const y = Math.round(item.transform[5]/ 5)* 5;
        if(!lines[y]){
            lines[y] = [];
        }
        lines[y].push(item.str);
    });
    const sortedLines = Object.keys(lines).sort((a , b)=> b - a).map(y => lines[y].join(" "));
    return sortedLines.join("\n");
}

function normalize(text){
    return text.replace(/\r\n/g,"\n").replace(/\r/g,"\n").split("\n").map(line => line.trim()).filter(line => line.length > 0).join("\n").replace(/[ \t]+/g," ");
}

async function logAction(req , action , target){
    const actorRole = req.headers["x-role"] || "UNKNOWN";
    const actor = actorRole;
    const actorId = actorRole;
    await recordEvent(actorId , actor , actorRole , action , target);
}

app.get("/verify",requireRole(["AUDITOR"]),async(req,res)=>{
    try{
        const result = await verifyAuditLog();
        res.status(200).json({result});
    }catch(err){
        res.status(500).json({err});
    }
    await logAction(req , "AUDIT_VERIFICATION" , "audit_log_chain");
});

app.get("/logs", requireRole(["AUDITOR"]),async(req,res)=>{
    try{
        const filters = {};
        const {actor , action , from , to} = req.query;
        if(actor){
            filters.actor = actor;
        }
        if(action){
            filters.action = action;
        }
        if(from || to){
            filters.timestamp = {};
            if(from){
                filters.time.$gte = new Date(from);
            }
            if(to){
                const toDate = new Date(to);
                toDate.setDate(toDate.getDate()+ 1);
                filters.time.$lte = toDate;
            }
        }
        const events = await getAuditLogs(filters);
        const cleaned = events.map(({prevHash, ...rest})=> rest);
        res.status(200).json({
            count : cleaned.length,
            logs : cleaned
        });
    }catch(err){
        res.status(500).json({err : err.message});
    }
    await logAction(req , "LOGS_VIEWED","audit_logs");
});

app.get("/verify/report" , requireRole(["AUDITOR"]),async(req , res)=>{
    let report;
    try{
        report = await generateVerificationReport();
        res.json(report);
    }catch(err){
        res.status(500).json({err : err.message});
    }
    await logAction(req , "REPORT_GENERATED" , report.reportId);
});

app.get("/verify/report/:reportId/download",async (req,res)=>{
    let report;
    try{
        const { reportId } = req.params;
        report = await VerificationReport.findOne({reportId}).lean();
        if(!report) return res.status(404).json({message : "Report not found"});
        generatePDFReport(report.renderedString , report.signature , res);
    }catch(err){
        res.status(500).json({err : err.message});
    }
    await logAction(req , "REPORT_DOWNLOADED" , report.reportId);
});

app.post("/verify/report/upload", upload.single("file"),async(req , res)=>{
    try {
        if(!req.file){
            return res.status(400).json({
                status : "INVALID REQUEST",
                message : "No file uploaded"
            });
        }
        const buffer = req.file.buffer;
        const text = await extractText(buffer);
        const signatureMatch = text.match(/BEGIN([\s\S]*?)END/);
        if(!signatureMatch){
            return res.status(400).json({
                status : "INVALID_REQUEST",
                message : "Signature Matching failed . Report may have been tampered with."
            });
        }
        const signature = signatureMatch[1].replace(/[^A-Za-z0-p+/=]/g,"").trim();
        console.log(signature);
        const report = text.replace(/BEGIN([\s\S]*?)END/,"").trim();
        const normalizedReport = normalize(report);
        const isValid = verifySignature(normalizedReport , signature);
        if(isValid){
            res.status(200).json({
                status : "VALID",
                message : "Signature is valid. Report is authentic and unmodified"
            });
        }
        else res.status(200).json({
            status : "INVALID",
            message : "Signature verification failed. Report may be tampered."
        });
        await logAction(req , "REPORT_VALIDATED" , (isValid)? "VALID" : "INVALID");
    }catch(err){
        res.status(500).json({err : err.message});
    }
});

app.get("/keys/public/fingerprint",async (req , res)=>{
    try{
        const fingerprint = getPublicKeyFingerprint();
        res.json({fingerprint});
    }catch(err){
        res.status(500).json({err : err.message});
    }
    await logAction(req ,"PUBLIC_KEY_ACCESSED","public_key");
});

// const events = getAuditLogs();
// console.log(verifyAuditLog(events));
// recordEvent("irfahn","LOGIN","system");
// recordEvent("malan","CHANGE_ROLE","irfahn");
// recordEvent("u1", "Alice", "ADMIN", "SYSTEM_START", "audit_service").catch(console.error);
// recordEvent("u2", "Bob", "AUDITOR", "DATA_ACCESS", "financial_records").catch(console.err);
// recordEvent("u1", "Alice", "ADMIN", "REPORT_GENERATED", "audit_report").catch(console.error);
// recordEvent("u3","Charlie","USER","LOGIN_FAILURE","authentication_service").catch(console.error);
// recordEvent("u2","Bob","AUDITOR","AUDIT_VERIFICATION","audit_log_chain").catch(console.error);
// recordEvent("u1","Alice","ADMIN","ROLE_UPDATED","user:u3").catch(console.error);

app.listen(3000,() => {
    console.log("Audit System running on port 3000");
});