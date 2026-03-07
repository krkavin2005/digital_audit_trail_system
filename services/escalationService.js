const Document = require("../models/Document");
const Notification = require("../models/Notification");
const Role = require("../models/Role");
const User = require("../models/User");
const WorkflowHistory = require("../models/WorkflowHistory");
const { SLA_RULES } = require("../workflow/documentWorkflow");
const cron = require("node-cron");
const { getSystemUser } = require("./systemService");
const { logAction } = require("./auditService");

const ESCALATION_BUFFER_DAYS = 2;

async function runEscalation(actor) {
    const documents = await Document.find({ isDeleted: false, isEscalated: false, status: { $in: ["SUBMITTED", "APPROVED"] } });
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

function startCronJobs() {
    cron.schedule("0 */6 * * *", async () => {
        try {
            console.log("Running scheduled escalation check");
            const systemUser = getSystemUser();
            const count = await runEscalation(systemUser);
            console.log(`Escalation completed. Escalated :${count}`);
        } catch (err) {
            console.error(err);
        }
    });
}

function shouldEscalate(doc) {
    console.log(doc.status);
    if (!SLA_RULES[doc.status]) return false;
    if (doc.isEscalated) return false;
    const now = new Date();
    const diffDays = (now - doc.statusChangedAt) / (1000 * 60 * 60 * 24);
    return diffDays > SLA_RULES[doc.status] + ESCALATION_BUFFER_DAYS;
}

module.exports = { runEscalation, startCronJobs, shouldEscalate };