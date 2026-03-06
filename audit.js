const express = require("express");
const fs = require("fs");
const crypto = require("crypto");
const { timeStamp, error } = require("console");
const PDFDocument = require("pdfkit");
const AuditEvent = require("./models/AuditEvent");
const { randomUUID } = require("crypto");
const VerificationReport = require("./models/VerificationReport");
const multer = require("multer");
const pdfjsLib = require("pdfjs-dist/legacy/build/pdf.js");
const app = express();
const privateKey = fs.readFileSync("private.pem", "utf8");
const publicKey = fs.readFileSync("public.pem", "utf8");
const upload = multer({ storage: multer.memoryStorage() });
const Role = require("./models/Role");
const User = require("./models/User");
const PERMISSIONS = require("./config/permissions");
const authMiddleware = require("./middleware/authMiddleware");
const permissionMiddleware = require("./middleware/permissionMiddleware");
const { report } = require("process");
require("dotenv").config();
const bcrypt = require("bcrypt");
const cors = require("cors");
const docupload = require("./config/multer");
const Document = require("./models/Document")
const path = require("path");
const { canTransition, canDelete, isOverdue, shouldEscalate } = require("./workflow/documentWorkflow");
const WorkflowHistory = require("./models/WorkflowHistory");
const cron = require("node-cron");
const { default: mongoose } = require("mongoose");
const Notification = require("./models/Notification");
const updateAuditAnchor = require("./utils/updateAuditAnchor");

let systemUser;

app.use(express.json());
app.use("/auth", require("./routes/auth"));
app.use("/test", require("./routes/test"));
app.use(cors());

async function getAuditLogs(obj) {
    return await AuditEvent.find(obj).sort({ eventId: 1 }).lean();
}

function canonicalStringify(obj) {
    return JSON.stringify(Object.keys(obj).sort().reduce((acc, key) => {
        acc[key] = obj[key];
        return acc;
    }, {}))
}

function computeHash(eventData, prevHash) {
    const payload = canonicalStringify(eventData);
    return crypto.createHash("sha256").update(payload + prevHash).digest("hex");
}

async function getPreviousHash() {
    const lastEvent = await AuditEvent.findOne({}).sort({ timestamp: -1 }).lean();
    return lastEvent ? lastEvent.hash : "0".repeat(64);
}

async function recordEvent(actorId, actor, actorRole, action, target) {
    const prevHash = await getPreviousHash();
    const last = await AuditEvent.findOne({}).sort({eventId : -1});
    const eventId = last ? last.eventId + 1 : 1;  
    const event = {
        eventId,
        actorId,
        actor,
        actorRole,
        action,
        target,
        timestamp: new Date()
    };
    const hash = computeHash(event, prevHash);
    await AuditEvent.create({ ...event, prevHash, hash });
    console.log("Recorded: ", hash);
    updateAuditAnchor(hash, eventId);
}

async function verifyAuditLog() {
    const anchor = JSON.parse(fs.readFileSync("audit-anchor.json", "utf8"));
    const events = await AuditEvent.find({}).sort({ eventId: 1 }).lean();
    const lastEvent = events[events.length - 1];
    if (anchor.lastHash !== lastEvent.hash) {
        return {
            valid: false,
            brokenAt: events.length - 1,
            expectedHash: anchor.lastHash,
            found: lastEvent.hash,
            expectedCount: anchor.eventCount,
            presentCount: events.length,
            tamperCode: 2
        };
    }
    if (events.length === 0) {
        return { valid: true, message: "No audit events found" };
    }
    let storedPrevHash = "0".repeat(64);
    for (let i = 0; i < events.length; i++) {
        const { _id, hash, prevHash, ...eventData } = events[i];
        if (storedPrevHash !== prevHash) {
            return {
                valid: false,
                brokenAt: i,
                expectedPrevHash: storedPrevHash,
                foundPrevHash: prevHash,
                tamperCode: 0
            }
        }
        const recomputedHash = computeHash(eventData, prevHash);
        if (recomputedHash !== hash) {
            return {
                valid: false,
                brokenAt: i,
                expected: recomputedHash,
                found: hash,
                tamperCode: 1
            };
        }
        storedPrevHash = hash;
    }
    return { valid: true };
}

function requireRole(allowedRoles) {
    return (req, res, next) => {
        const role = req.headers["x-role"];
        if (!role) {
            return res.status(401).json({
                status: "DENIED",
                message: "Role not provided"
            });
        }
        if (!allowedRoles.includes(role)) {
            return res.status(403).json({
                status: "FORBIDDEN",
                message: "Unprevileged access"
            });
        }
        next();
    };
}

async function generateVerificationReport() {
    const result = await verifyAuditLog();
    const report = {
        reportId: randomUUID(),
        verifiedAt: new Date().toISOString(),
        totalRecords: await AuditEvent.countDocuments(),
        verifier: "SYSTEM"
    };
    if (result.valid) {
        report.status = "VALID";
    }
    else {
        report.status = "TAMPERED";
        report.brokenAt = result.brokenAt;
        if (!result.tamperCode) {
            report.expectedPrevHash = result.expectedPrevHash;
            report.foundPrevHash = result.foundPrevHash;
        }
        else{
            report.expectedHash = result.expected;
            report.foundHash = result.found;
            if(result.tamperCode == 2){
                report.expectedCount = result.expectedCount;
                report.presentCount = result.presentCount;
            }
        }
        report.tamperCode = result.tamperCode;
    }
    const renderedReport = buildRenderedReport(report);
    const normalized = normalize(renderedReport);
    report.renderedString = normalized;
    report.signature = signReport(normalized);
    await VerificationReport.create(report);
    return report;
}

function generatePDFReport(report, signature, res) {
    try {
        const time = report.match(/Verification Time\s*:\s*(.+)/);
        if (!time) throw new Error("Verification Time not found");
        const verifiedAt = time[1].trim();
        const doc = new PDFDocument({ margin: 50 });
        res.setHeader("Content-Type", "application/pdf");
        res.setHeader("Content-Disposition", `attachment; filename="audit_report_${verifiedAt.replace(/:/g, "_")}.pdf"`);
        doc.pipe(res);
        const lines = report.split("\n");
        doc.fontSize(18).text(lines[0], { align: "center" });
        doc.moveDown(2);
        doc.fontSize(12);
        for (let line of lines.slice(1)) {
            if (line.startsWith("Status : ")) {
                const statusvalue = line.replace("Status : ", "");
                doc.text("Status : ", { continued: true });
                if (statusvalue === "VALID") {
                    doc.fillColor("green").text("VALID");
                }
                else {
                    doc.fillColor("red").text("TAMPERED");
                }
                doc.moveDown(1);
            }
            else if (line.startsWith("This")) {
                doc.moveDown(2);
                doc.fillColor("black").text(line);
            }
            else doc.text(line);
        };
        doc.moveDown(2);
        doc.fillColor("white").fontSize(6);
        doc.text("BEGIN-----")
        doc.text(signature, { width: 500 });
        doc.text("-----END");
        doc.end();
    } catch (err) {
        res.status(500).json({ err: err.message });
    }
}

function signReport(report) {
    const hash = crypto.createHash("sha256").update(report).digest();
    const signature = crypto.sign("RSA-SHA256", hash, privateKey);
    return signature.toString("base64");
}

function verifySignature(report, signature) {
    const hash = crypto.createHash("sha256").update(report).digest();
    return crypto.verify("RSA-SHA256", hash, publicKey, Buffer.from(signature, "base64"));
}

function getPublicKeyFingerprint() {
    return crypto.createHash("sha256").update(publicKey).digest("hex");
}

function buildRenderedReport(report) {
    let lines = [];
    lines.push("AUDIT TRAIL VERIFICATION REPORT");
    lines.push("");
    lines.push(`Verification Time : ${report.verifiedAt}`);
    lines.push(`Total Records Checked : ${report.totalRecords}`);
    lines.push(`Status : ${report.status}`);
    lines.push("");
    if (report.status === "TAMPERED") {
        lines.push("Audit trail integrity violation detected.");
        lines.push("");
        lines.push(`Broken At Index : ${report.brokenAt}`);
        if (report.tamperCode) {
            lines.push(`Expected Hash : ${report.expectedHash}`);
            lines.push(`Found Hash : ${report.foundHash}`);
            if(report.tamperCode == 2){
                lines.push(`Expected Count : ${report.expectedCount}`);
                lines.push(`Present Count : ${report.presentCount}`);
                lines.push(`Log truncation detected.`);
            }
        }
        else {
            lines.push(`Expected Previous Hash : ${report.expectedPrevHash}`);
            lines.push(`Found Previous Hash : ${report.foundPrevHash}`);
        }
    }
    else {
        lines.push("Audit trail integration verified successfully.");
    }
    lines.push("");
    lines.push("This report was generated by the Audit Trail System");
    return lines.join("\n");
}

async function extractText(buffer) {
    const uint8array = new Uint8Array(buffer);
    const loadingTask = pdfjsLib.getDocument({ data: uint8array });
    const pdf = await loadingTask.promise;
    const page = await pdf.getPage(1);
    const textContent = await page.getTextContent();
    const lines = {};
    textContent.items.forEach(item => {
        const y = Math.round(item.transform[5] / 5) * 5;
        if (!lines[y]) {
            lines[y] = [];
        }
        lines[y].push(item.str);
    });
    const sortedLines = Object.keys(lines).sort((a, b) => b - a).map(y => lines[y].join(" "));
    return sortedLines.join("\n");
}

function normalize(text) {
    return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n").map(line => line.trim()).filter(line => line.length > 0).join("\n").replace(/[ \t]+/g, " ");
}

async function logAction(user, action, target) {
    const { userId, username, role } = user;
    const actorRole = role.roleName;
    const actor = username;
    const actorId = userId;
    await recordEvent(actorId, actor, actorRole, action, target);
}

async function runEscalation(actor) {
    const documents = await Document.find({ isDeleted: false, isEscalated: false , status : {$in :["SUBMITTED ","APPROVED"]}});
    let escalatedCount = 0;
    const adminRole = await Role.findOne({ roleName: "ADMIN" });
    const admins = await User.find({ role: adminRole._id });
    for (const doc of documents) {
        if (shouldEscalate(doc)) {
            doc.isEscalated = true;
            doc.escalatedAt = new Date();
            await doc.save();
            await WorkflowHistory.create({
                documentId: doc.documentId,
                fromState: doc.status,
                toState: doc.status,
                actedBy: actor._id,
                actorRole: actor.role.roleName,
                comment: "Auto escalation due to SLA breach"
            });
            await logAction(actor, "DOCUMENT_ESCALATED", doc.documentId);
            const recepients = new Map();
            admins.forEach(admin => recepients.set(admin._id.toString(), admin._id));
            recepients.set(doc.uploadedBy.toString(), doc.uploadedBy);
            await Notification.insertMany(Array.from(recepients.values()).map(userId => ({
                userId,
                type: "ESCALATION",
                documentId: doc.documentId,
                message: `Document "${doc.originalName}" has been escalated due to SLA breach`
            })));
            escalatedCount++;
        }
    }
    return escalatedCount;
}

async function initSystemUser() {
    systemUser = await User.findOne({ username: "SYSTEM" }).populate("role");
    if (!systemUser) throw new Error("SYSTEM user not found");
}

function startCronJobs() {
    cron.schedule("0 */6 * * *", async () => {
        try {
            console.log("Running scheduled escalation check");
            const count = await runEscalation(systemUser);
            console.log(`Escalation completed. Escalated :${count}`);
        } catch (err) {
            console.error(err);
        }
    });
}

app.get("/verify", authMiddleware, permissionMiddleware(PERMISSIONS.VERIFY_AUDIT), async (req, res) => {
    try {
        const result = await verifyAuditLog();
        res.status(200).json({ result });
    } catch (err) {
        res.status(500).json({ err });
    }
    await logAction(req.user, "AUDIT_VERIFICATION", "audit_log_chain");
});

app.get("/logs", authMiddleware, permissionMiddleware(PERMISSIONS.AUDIT_VIEW), async (req, res) => {
    try {
        const filters = {};
        const { actor, action, from, to } = req.query;
        if (actor) {
            filters.actor = actor;
        }
        if (action) {
            filters.action = action;
        }
        if (from || to) {
            filters.timestamp = {};
            if (from) {
                filters.timestamp.$gte = new Date(from);
            }
            if (to) {
                const toDate = new Date(to);
                toDate.setDate(toDate.getDate() + 1);
                filters.timestamp.$lt = toDate;
            }
        }
        const events = await getAuditLogs(filters);
        const cleaned = events.map(({ prevHash, ...rest }) => rest);
        res.status(200).json({
            count: cleaned.length,
            logs: cleaned
        });
    } catch (err) {
        res.status(500).json({ err: err.message });
    }
    await logAction(req.user, "LOGS_VIEWED", "audit_logs");
});

app.get("/verify/report", authMiddleware, permissionMiddleware(PERMISSIONS.REPORT_GENERATE), async (req, res) => {
    let report;
    try {
        report = await generateVerificationReport();
        res.json(report);
    } catch (err) {
        res.status(500).json({ err: err.message });
    }
    await logAction(req.user, "REPORT_GENERATED", report.reportId);
});

app.get("/verify/report/:reportId/download", authMiddleware, permissionMiddleware(PERMISSIONS.REPORT_DOWNLOAD), async (req, res) => {
    let report;
    try {
        const { reportId } = req.params;
        report = await VerificationReport.findOne({ reportId }).lean();
        if (!report) return res.status(404).json({ message: "Report not found" });
        generatePDFReport(report.renderedString, report.signature, res);
    } catch (err) {
        res.status(500).json({ err: err.message });
    }
    await logAction(req.user, "REPORT_DOWNLOADED", report.reportId);
});

app.post("/verify/report/upload", authMiddleware, permissionMiddleware(PERMISSIONS.REPORT_VALIDATE), upload.single("file"), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                status: "INVALID REQUEST",
                message: "No file uploaded"
            });
        }
        const buffer = req.file.buffer;
        const text = await extractText(buffer);
        const signatureMatch = text.match(/BEGIN([\s\S]*?)END/);
        if (!signatureMatch) {
            return res.status(400).json({
                status: "INVALID_REQUEST",
                message: "Signature Matching failed . Report may have been tampered with."
            });
        }
        const signature = signatureMatch[1].replace(/[^A-Za-z0-p+/=]/g, "").trim();
        console.log(signature);
        const report = text.replace(/BEGIN([\s\S]*?)END/, "").trim();
        const normalizedReport = normalize(report);
        const isValid = verifySignature(normalizedReport, signature);
        if (isValid) {
            res.status(200).json({
                status: "VALID",
                message: "Signature is valid. Report is authentic and unmodified"
            });
        }
        else res.status(200).json({
            status: "INVALID",
            message: "Signature verification failed. Report may be tampered."
        });
        await logAction(req.user, "REPORT_VALIDATED", (isValid) ? "VALID" : "INVALID");
    } catch (err) {
        res.status(500).json({ err: err.message });
    }
});

app.get("/keys/public/fingerprint", async (req, res) => {
    try {
        const fingerprint = getPublicKeyFingerprint();
        res.json({ fingerprint });
    } catch (err) {
        res.status(500).json({ err: err.message });
    }
    await logAction(req.user, "PUBLIC_KEY_ACCESSED", "public_key");
});

app.get("/reports", authMiddleware, permissionMiddleware(PERMISSIONS.REPORT_DOWNLOAD), async (req, res) => {
    try {
        const reports = await VerificationReport.find({}).sort({ verifiedAt: -1 });
        res.json({
            count: reports.length,
            reports
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.post("/users", authMiddleware, permissionMiddleware(PERMISSIONS.USER_CREATE), async (req, res) => {
    try {
        const { email, password, roleName, username } = req.body;
        if (!email || !password || !roleName || !username) {
            return res.status(400).json({ message: "Missing required fields" });
        }
        const exist = await User.findOne({ email });
        if (exist) {
            return res.status(409).json({ message: "User already exists" });
        }
        const role = await Role.findOne({ roleName: roleName.toUpperCase() });
        if (!role) {
            return res.status(404).json({ message: "Role not found" });
        }
        const passwordHash = await bcrypt.hash(password, 10);
        const newUser = await User.create({
            username,
            email,
            passwordHash,
            role: role._id
        });
        await logAction(req.user, "USER_CREATION", "user");
        res.status(201).json({
            message: "User created",
            userId: newUser.userId
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.patch("/users/:userId/role", authMiddleware, permissionMiddleware(PERMISSIONS.USER_PROMOTE), async (req, res) => {
    try {
        const { userId } = req.params;
        console.log(userId);
        const { roleName } = req.body;
        if (!roleName) {
            return res.status(400).json({ message: "rolename is required" });
        }
        const targetUser = await User.findOne({ userId });
        if (!targetUser) {
            return res.status(404).json({ message: "User not found" });
        }
        const newRole = await Role.findOne({ roleName: roleName.toUpperCase() });
        if (!newRole) {
            return res.status(400).json({ message: "Role not found" });
        }
        if (req.user.userId === targetUser.userId) {
            return res.status(400).json({ message: "Cannot modify your own role" });
        }
        targetUser.role = newRole._id;
        await targetUser.save();
        await logAction(req.user, "USER_PROMOTION", "user");
        return res.status(200).json({
            message: "User role updated successfully",
            updateUserId: targetUser.userId,
            newRole: newRole.roleName
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Server error" });
    }
});

app.patch("/users/:userId/deactivate", authMiddleware, permissionMiddleware(PERMISSIONS.USER_DELETE), async (req, res) => {
    try {
        const { userId } = req.params;
        const targetUser = await User.findOne({ userId });
        if (!targetUser) {
            return res.status(404).json({ message: "User not found" });
        }
        if (req.user.userId === targetUser.userId) {
            return res.status(400).json({ message: "Cannot deactivate own account" });
        }
        if (!targetUser.isActive) {
            return res.status(400).json({ message: "User already deactivated" });
        }
        targetUser.isActive = false;
        await targetUser.save();
        await logAction(req.user, "USER_DEACTIVATION", "user");
        return res.json({
            message: "User deactivated successfully",
            userId: targetUser.userId
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: err.message });
    }
});

app.get("/users", authMiddleware, permissionMiddleware(PERMISSIONS.USER_LIST), async (req, res) => {
    try {
        const users = await User.find().populate("role").select("-passwordHash");
        console.log(users);
        const formatted = users.map(user => ({
            userId: user.userId,
            username: user.username,
            email: user.email,
            role: user.role.roleName,
            isActive: user.isActive,
            createdAt: user.createdAt
        }));
        await logAction(req.user, "USER_LIST", "user");
        return res.json({
            count: formatted.length,
            users: formatted
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: err.message });
    }
});

app.patch("/users/:userId/reactivate", authMiddleware, permissionMiddleware(PERMISSIONS.USER_DELETE), async (req, res) => {
    try {
        const { userId } = req.params;
        const targetUser = await User.findOne({ userId });
        if (!targetUser) {
            return res.status(404).json({ message: "User Not Found" });
        }
        if (targetUser.isActive) {
            return res.status(400).json({ message: "User is already active" });
        }
        targetUser.isActive = true;
        await targetUser.save();
        await logAction(req.user, "USER_REACTIVATION", "user");
        res.status(200).json({ message: "User reactivated", userId: targetUser.userId });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: err.message });
    }
});

app.get("/users/:userId", authMiddleware, permissionMiddleware(PERMISSIONS.USER_LIST), async (req, res) => {
    try {
        const { userId } = req.params;
        const user = await User.findOne({ userId }).populate("role").select("-passwordHash");
        if (!user) return res.status(404).json({ message: "User not found" });
        await logAction(req.user, "USER_VIEW", "user");
        return res.json({
            user: {
                userId: user.userId,
                username: user.username,
                email: user.email,
                role: user.role.roleName,
                isActive: user.isActive,
                createdAt: user.createdAt
            }
        });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: err.message });
    }
});

app.post("/documents/upload", authMiddleware, permissionMiddleware(PERMISSIONS.FILE_UPLOAD), docupload.single("file"), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: "No file uploaded" });
        }
        console.log(req.file);
        const fileBuffer = fs.readFileSync(req.file.path);
        const fileHash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
        const newDoc = await Document.create({
            originalName: req.file.originalname,
            storedName: req.file.filename,
            uploadedBy: req.user._id,
            fileHash,
            size: req.file.size,
            mimeType: req.file.mimetype
        });
        await WorkflowHistory.create({
            documentId: newDoc.documentId,
            fromState: "INITIAL",
            toState: "DRAFT",
            actedBy: req.user._id,
            actorRole: req.user.role.roleName
        });
        await logAction(req.user, "FILE_UPLOAD", newDoc.documentId);
        res.status(200).json({
            message: "File uploaded",
            document: newDoc
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
});

app.get("/documents", authMiddleware, permissionMiddleware(PERMISSIONS.FILE_VIEW), async (req, res) => {
    try {
        const { uploadedBy, mimeType, from, to, search, page = 1, limit = 10 } = req.query;
        const filter = { isDeleted: false };
        if (uploadedBy) filter.uploadedBy = uploadedBy;
        if (mimeType) filter.mimeType = mimeType;
        if (from || to) {
            filter.createdAt = {};
            if (from) filter.createdAt.$gte = new Date(from);
            if (to) {
                const toDate = new Date(to);
                toDate.setDate(toDate.getDate() + 1);
                filter.createdAt.$lt = toDate;
            }
        }
        if (search) {
            filter.originalName = {
                $regex: search,
                $options: "i"
            };
        }
        const documents = await Document.find(filter).populate("uploadedBy", "username email").sort({ createdAt: -1 }).skip((page - 1) * limit).limit(Number(limit)).select("-storedName -__v");
        const total = await Document.countDocuments(filter);
        await logAction(req.user, "FILE_LIST", "Documents");
        res.status(200).json({ total, page: Number(page), limit: Number(limit), documents });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
});

app.get("/documents/:documentId", authMiddleware, permissionMiddleware(PERMISSIONS.FILE_VIEW), async (req, res) => {
    try {
        const { documentId } = req.params;
        const mode = req.query.mode || "download";
        const document = await Document.findOne({ documentId, isDeleted: false });
        if (!document) return res.status(404).json({ message: "Document not found" });
        const filePath = path.join(__dirname, "uploads", document.storedName);
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ message: "File not found" });
        }
        const fileBuffer = fs.readFileSync(filePath);
        const computedHash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
        if (computedHash !== document.fileHash) {
            return res.status(500).json({ message: "File integrity check failed. File may have been tampered." });
        }
        await logAction(req.user, "FILE_ACCESS", document.documentId);
        if (mode === "view") {
            res.setHeader("Content-type", document.mimeType);
            res.setHeader("Content-Disposition", `inline; filename="${document.originalName}"`);
            return res.status(200).sendFile(filePath);
        }
        return res.status(200).download(filePath, document.originalName);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
});

app.delete("/documents/:documentId", authMiddleware, permissionMiddleware(PERMISSIONS.FILE_DELETE), async (req, res) => {
    try {
        const { documentId } = req.params;
        const document = await Document.findOne({ documentId, isDeleted: false });
        if (!document) return res.status(400).json({ message: "Document not found" });
        if (!canDelete(document, req.user)) {
            return res.status(403).json({ message: "Deletion not allowed in current state" });
        }
        document.isDeleted = true;
        await document.save();
        await logAction(req.user, "FILE_DELETION", documentId);
        res.status(200).json({ message: "File deleted", documentId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
});

app.patch("/documents/:documentId/transition", authMiddleware, async (req, res) => {
    try {
        const { documentId } = req.params;
        const { toState, managerId } = req.body;
        const document = await Document.findOne({ documentId, isDeleted: false }).populate("uploadedBy","username");
        if (!document) return res.status(404).json({ message: "Document not found" });
        const result = canTransition(document, toState, req.user, req.body.comment);
        if (!result.allowed) {
            return res.status(403).json({ message: result.reason });
        }
        if (toState === "SUBMITTED") {
            if (!managerId) return res.status(400).json({ message: "Reviewer required" });
            document.assignedTo = managerId;
            await Notification.insertOne({
                userId : managerId,
                type :"SUBMISSION",
                documentId,
                message :`Document ${document.originalName} submitted by ${document.uploadedBy.username} for approval.`
            });
        }
        if (toState === "DRAFT") document.assignedTo = null;
        if(toState ==="APPROVED"|| toState ==="REJECTED" || toState ==="ARCHIVED"){
            await Notification.insertOne({
                userId : document.uploadedBy._id,
                type : "ACTION",
                documentId,
                message :`Document ${document.originalName} ${toState.toLowerCase()}` 
            });
        }
        const fromState = document.status;
        document.status = toState;
        document.statusChangedAt = new Date();
        await document.save();
        console.log(req.body);
        await WorkflowHistory.create({
            documentId,
            fromState,
            toState,
            actedBy: req.user._id,
            actorRole: req.user.role.roleName,
            comment: req.body.comment || null
        })
        await logAction(req.user, `Document ${document.status}`, document.documentId);
        res.status(200).json({ message: "Status updated", status: document.status });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
});

app.get("/documents/:documentId/history", authMiddleware, permissionMiddleware(PERMISSIONS.FILE_VIEW), async (req, res) => {
    try {
        const { documentId } = req.params;
        const history = await WorkflowHistory.find({ documentId }).populate("actedBy", "username email").sort({ createdAt: 1 });
        res.json({ count: history.length, history });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
});

app.get("/workflow/pending", authMiddleware, async (req, res) => {
    try {
        const role = req.user.role.roleName;
        const userId = req.user._id;
        let query = {};
        if (role === "MANAGER") {
            query.status = "SUBMITTED";
            query.assignedTo = userId;
        }
        else if (role === "ADMIN") {
            query.$or = [{ status: "APPROVED" }, { status: "SUBMITTED", assignedTo: userId }];
        }
        else if (role === "EMPLOYEE") {
            query.status = { $in: ["REJECTED", "DRAFT"] };
            query.uploadedBy = userId;
        }
        const docs = await Document.find(query).populate("uploadedBy", "username email -_id").select("documentId originalName status uploadedBy createdAt statusChangedAt isEscalated").sort({ createdAt: -1 });
        const updated = docs.map(doc => ({
            ...doc.toObject(),
            isOverdue: isOverdue(doc)
        }));
        res.status(200).json({ count: updated.length, documents: updated });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
});

app.get("/workflow/my-submissions", authMiddleware, async (req, res) => {
    try {
        const docs = await Document.find({ uploadedBy: req.user._id }).select("documentId originalName status createdAt").sort({ createdAt: -1 });
        res.status(200).json({ count: docs.length, documents: docs });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
});

app.get("/workflow/dashboard-summary", authMiddleware, async (req, res) => {
    try {
        const summary = await Document.find({ isDeleted: false });
        const counts = {
            DRAFT: 0,
            SUBMITTED: 0,
            APPROVED: 0,
            REJECTED: 0,
            ARCHIVED: 0,
            OVERDUE: 0,
            ESCALATED: 0
        };
        summary.forEach(doc => {
            const status = doc.status;
            if (counts[status] !== undefined) counts[status]++;
            if (isOverdue(doc)) counts.OVERDUE++;
            if (doc.isEscalated) counts.ESCALATED++;
        });
        const total = summary.length;
        res.status(200).json({ total, counts });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
});

app.post("/workflow/run-escalation", authMiddleware, async (req, res) => {
    try {
        const count = await runEscalation(req.user);
        await logAction(req.user, "ESCALATION_RUN_MANUAL", "workflow");
        res.status(200).json({
            message: "Escalation run completed",
            escalated: count
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
});

app.get("/notifications", authMiddleware, async (req, res) => {
    try {
        const notifications = await Notification.find({ userId: req.user._id }).sort({ createdAt: -1 });
        res.status(200).json(notifications);
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
});

app.get("/notifications/unread-count", authMiddleware, async (req, res) => {
    try {
        const count = await Notification.countDocuments({ userId: req.user._id, isRead: false });
        res.status(200).json({ unread: count });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
});

app.patch("/notifications/:id/read", authMiddleware, async (req, res) => {
    try {
        await Notification.updateOne({ _id: req.params.id, userId: req.user._id }, { $set: { isRead: true } });
        res.status(200).json({ message: "Marked as read" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
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

mongoose.connection.once("open", async () => {
    await initSystemUser();
    const count = await runEscalation(systemUser);
    console.log(`Sartup Escalation. Escalated :${count}`);
    startCronJobs();

    app.listen(process.env.PORT, () => {
        console.log("Audit System running on port 3000");
    });
});