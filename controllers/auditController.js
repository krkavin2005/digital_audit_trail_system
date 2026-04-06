const { getAuditLogs, logAction } = require("../services/auditService");

exports.getLogs = async (req, res) => {
    try {
        const filters = {};
        const { actorId , action, from, to } = req.query;
        if (actorId) {
            filters.actorId = actorId;
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
        console.error(err);
        res.status(500).json({ err: err.message });
    }
};