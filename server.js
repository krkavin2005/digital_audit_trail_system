const express = require("express");
const app = express();
require("dotenv").config();
const cors = require("cors");
const { default: mongoose } = require("mongoose");
const { runEscalation, startCronJobs } = require("./services/escalationService");
const { initSystemUser, getSystemUser } = require("./services/systemService");

app.use(express.json());
app.use(cors());
app.use("/auth", require("./routes/auth"));
app.use("/test", require("./routes/test"));
app.use("/users", require("./routes/userRoutes"));
app.use("/documents", require("./routes/documentRoutes"));
app.use("/workflow", require("./routes/workflowRoutes"));
app.use("/notifications", require("./routes/notificationRoutes"));
app.use("/verify", require("./routes/verificationRoutes"));
app.use("/audit", require("./routes/auditRoutes"));

mongoose.connection.once("open", async () => {
    await initSystemUser();
    const systemUser = getSystemUser();
    const count = await runEscalation(systemUser);
    console.log(`Sartup Escalation. Escalated :${count}`);
    startCronJobs();

    app.listen(process.env.PORT, () => {
        console.log("Audit System running on port 3000");
    });
});