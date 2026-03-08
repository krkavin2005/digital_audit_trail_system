const Document = require("../models/Document");
const { logAction } = require("../services/auditService");
const { runEscalation } = require("../services/escalationService");
const { isOverdue } = require("../workflow/documentWorkflow");

exports.getPendingWorks = async (req, res) => {
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
};

exports.getMySubmissions = async (req, res) => {
    try {
        const docs = await Document.find({ uploadedBy: req.user._id }).select("documentId originalName status createdAt").sort({ createdAt: -1 });
        res.status(200).json({ count: docs.length, documents: docs });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: err.message });
    }
};

exports.getDashboardSummary = async (req, res) => {
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
};

exports.runEscalationManual = async (req, res) => {
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
};