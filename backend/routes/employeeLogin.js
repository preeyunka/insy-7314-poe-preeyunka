const express = require("express");
const router = express.Router();
const { Employee } = require("../models");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

router.post("/", async (req, res) => {
    try {
        const { email, password } = req.body;

        const employee = await Employee.findOne({ where: { email } });
        if (!employee) return res.status(401).json({ message: "Invalid email" });

        const isValid = await bcrypt.compare(password, employee.password);
        if (!isValid) return res.status(401).json({ message: "Invalid password" });

        const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: "1h" });
        res.json({ token, email });
    } catch (err) {
        console.error("Employee login error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

module.exports = router;
