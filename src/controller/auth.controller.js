const user = require("../models/user.model");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const config = require("../config/config");

exports.register = async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const isalreadyExist = await user.findOne({
            $or: [{ email }, { username }]
        });
        if (isalreadyExist) {
            return res.status(400).json({ message: "User already exists" });
        }
        const hashpassword = crypto.createHash("sha256").update(password).digest("hex");
        const newUser = await user.create({ username, email, password: hashpassword });
        const token = jwt.sign({ id: newUser._id }, config.JWT_SECRET, { expiresIn: "1d" });
        res.status(201).json({ 
            message: "User registered successfully",
            user: newUser,
            token: token
        });

    } catch (error) {
        res.status(500).json({ message: "Internal server error" });

    }


};

