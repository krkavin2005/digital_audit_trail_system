const fs = require("fs");
const crypto = require("crypto");
const Document = require("../models/Document");
const WorkflowHistory = require("../models/WorkflowHistory");
const { logAction } = require("../services/auditService");
const path = require("path");
const { canTransition, canDelete } = require("../workflow/documentWorkflow");
const Notification = require("../models/Notification");

exports.uploadDocument = async (req, res) => {
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
};

exports.listDocuments = async (req, res) => {
    try {
        const { uploadedBy, mimeType, from, to, search, page = 1, limit = 10 , status} = req.query;
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
        if (status) {
            if(status ==="OVERDUE") filter.isOverdue = true;
            else if(status ==="ESCALATED") filter.isEscalated = true;
            else filter.status = status;
        }
        const documents = await Document.find(filter).populate("uploadedBy", "username email").populate("assignedTo","username email").sort({ createdAt: -1 }).skip((page - 1) * limit).limit(Number(limit)).select("-storedName -__v");
        const total = await Document.countDocuments(filter);
        // await logAction(req.user, "FILE_LIST", "Documents");
        res.status(200).json({ total, page: Number(page), limit: Number(limit), documents });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
};

exports.getDocument = async (req, res) => {
    try {
        const { documentId } = req.params;
        const mode = req.query.mode || "download";
        const document = await Document.findOne({ documentId, isDeleted: false });
        if (!document) return res.status(404).json({ message: "Document not found" });
        const filePath = path.join(__dirname, "../uploads", document.storedName);
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
};

exports.deleteDocument = async (req, res) => {
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
};

exports.transitionDocument = async (req, res) => {
    try {
        const { documentId } = req.params;
        const { toState, managerId } = req.body;
        const document = await Document.findOne({ documentId, isDeleted: false }).populate("uploadedBy", "username");
        if (!document) return res.status(404).json({ message: "Document not found" });
        const result = canTransition(document, toState, req.user, req.body.comment);
        if (!result.allowed) {
            return res.status(403).json({ message: result.reason });
        }
        if (toState === "SUBMITTED") {
            if (!managerId) return res.status(400).json({ message: "Reviewer required" });
            document.assignedTo = managerId;
            console.log(managerId);
            
            await Notification.insertOne({
                userId: managerId,
                type: "SUBMISSION",
                documentId,
                message: `Document ${document.originalName} submitted by ${document.uploadedBy.username} for approval.`
            });
        }
        if (toState === "DRAFT") document.assignedTo = null;
        if (toState === "APPROVED" || toState === "REJECTED" || toState === "ARCHIVED") {
            await Notification.insertOne({
                userId: document.uploadedBy._id,
                type: "ACTION",
                documentId,
                message: `Document ${document.originalName} ${toState.toLowerCase()}`
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
};

exports.getDocumentHistory = async (req, res) => {
    try {
        const { documentId } = req.params;
        const history = await WorkflowHistory.find({ documentId }).populate("actedBy", "username email").sort({ createdAt: 1 });
        res.json({ count: history.length, history });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
};