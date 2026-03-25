const user = require("../models/user.model");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const config = require("../config/config");
const session = require("../models/session.model");

exports.register = async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const isalreadyExist = await user.findOne({
      $or: [{ email }, { username }],
    });

    if (isalreadyExist) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashpassword = crypto
      .createHash("sha256")
      .update(password)
      .digest("hex");

    const newUser = await user.create({
      username,
      email,
      password: hashpassword,
    });

    const refreshToken = jwt.sign({ id: newUser._id }, config.JWT_SECRET, {
      expiresIn: "7d",
    });

    /**
     * res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
     */
    hashRefreshToken = crypto
        .createHash("sha256")
        .update(refreshToken)
        .digest("hex");

    const Session = await session.create({
        userId: newUser._id,
        refreshTokenHash: hashRefreshToken,
        ip: req.ip,
        useerAgent: req.headers["user-agent"],
    });

    const accessToken = jwt.sign(
        { 
            id: newUser._id,
            sessionId: session._id,
        }, 
        config.JWT_SECRET, 
        {
            expiresIn: "15m", 
        }
   );

    res.status(201).json({
      message: "User registered successfully",
      user: newUser,
      token: token,
    });
    
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
};

exports.getme = async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "token not found" });
    }
    const decoded = jwt.verify(token, config.JWT_SECRET);
    console.log("Decoded Token:", decoded);
    res.status(200).json({ decoded });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
};

exports.refreshToken = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ message: "Refresh Token not found" });
    }
    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);
    const accessToken = jwt.sign({ id: decoded.id }, config.JWT_SECRET, {
      expiresIn: "15m",
    });
    res.status(200).json({ message: "Refresh Token successful", accessToken });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
};
