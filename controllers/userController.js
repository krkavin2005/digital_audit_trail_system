const Role = require("../models/Role");
const User = require("../models/User");
const bcrypt = require("bcrypt");
const { logAction } = require("../services/auditService");

exports.createUser = async (req, res) => {
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
};