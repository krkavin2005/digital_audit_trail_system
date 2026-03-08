const { getAuditLogs, logAction } = require("../services/auditService");

exports.getLogs = async (req, res) => {
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
        await logAction(req.user, "LOGS_VIEWED", "audit_logs");
        res.status(200).json({
            count: cleaned.length,
            logs: cleaned
        });
    } catch (err) {
        res.status(500).json({ err: err.message });
    }
};