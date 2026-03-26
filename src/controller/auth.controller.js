const user = require("../models/user.model");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const config = require("../config/config");
const session = require("../models/session.model");
const { sendEmail } = require("../services/email.services");
const { otpModel } = require("../models/otp.model");
const { generateOTP, getOtpHtml } = require("../utiles/util"); 

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

    const otp = generateOTP();
    const html = getOtpHtml(otp);
    const expairesAt = new Date(Date.now() + 5 * 60 * 1000); // OTP valid for 10 minutes    
    const hashotp = crypto.createHash("sha256").update(otp).digest("hex");
    await otpModel.create({
      user: newUser._id,
      hashotp,
      expiresAt: expairesAt
    });
    await sendEmail(email, "Verification OTP", `Your OTP is ${otp}`, html);

    res.status(201).json({
        message: "User registered successfully",
        user: {
            username: newUser.username,
            email: newUser.email,
            verified: newUser.verified
        },
    })
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const existingUser = await user.findOne({ email });

    if (!existingUser) {
      return res.status(400).json({ message: "Invalid email."});
    }

    const isMatch = await existingUser.comparePassword(password);

    if (!isMatch) {
      return res.status(400).json({ message: "Invalid  password" });
    }

     if (!existingUser.verified) {
        return res.status(401).json({
            message: "Email not verified"
        })
    }

    const refreshToken = jwt.sign({ id: existingUser._id }, config.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    const hashRefreshToken = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");

    const Session = await session.create({
      userId: existingUser._id,
      refreshTokenHash: hashRefreshToken,
      ip: req.ip,
      userAgent: req.headers["user-agent"],
    });

    const accessToken = jwt.sign(
      {
        id: existingUser._id,
        sessionId: Session._id,
      },
      config.JWT_SECRET,
      {
        expiresIn: "15m",
      },
    );

    res.status(200).json({
      message: "Login successful",
      user: existingUser,
    
    });
  } catch (error) {
    res.status(500).json({ message: "Failed to login" });

  }
}

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

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
        
        const Session = await session.findOne({
            refreshTokenHash,
            revoked: false
        })

    if(!Session) {
            return res.status(401).json({
                message: "session not found"
            })
        }

    const accessToken = jwt.sign({ id: decoded.id }, config.JWT_SECRET, {
      expiresIn: "15m",
    });

    const newRefreshToken = jwt.sign({ id: decoded.id }, config.JWT_SECRET, {
      expiresIn: "7d",
    });

    const newRefreshTokenHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex");

    Session.refreshTokenHash = newRefreshTokenHash;
    await Session.save();

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({ message: "Refresh Token successful", accessToken });
  } catch (error) {
    res.status(500).json({ message: "issue while refreshing token creation" });
  }
};

exports.logout = async (req, res) => {
    try {
        const refreshToken = req.cookies.refreshToken;
        
        if (!refreshToken) {
            return res.status(401).json(
                {
                    message: "Refresh Token not found"
                }
            )
        }

        const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
        
        const Session = await session.findOne({
            refreshTokenHash,
            revoked: false
        })

        if(!Session) {
            return res.status(401).json({
                message: "session not found"
            })
        }

        Session.revoked = true;
        await Session.save();

        res.clearCookie("refreshToken");
        return res.status(200).json({
            message: "Logout successfully"
        })
    }catch(error){
        return res.status(500).json({
            message: error.message
        })
    }
};

exports.logoutAll = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ message: "Refresh Token not found" });
  }

  const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

  await session.updateMany(
    { userId: decoded.id, revoked: false },
    { revoked: true }
  );

  res.clearCookie("refreshToken");
  return res.status(200).json({ message: "Logged out from all sessions" });   
};

exports.verifyOtp = async (req, res) => {
    try {
        const { email, otp } = req.body;
        const hashotp = crypto.createHash("sha256").update(otp).digest("hex");

        const otpdoc = await otpModel.findOne({ email, hashotp });

        if (!otpdoc) {
            return res.status(400).json({ message: "Invalid OTP" });
        }

        if (otpdoc.expiresAt < new Date()) {
            return res.status(400).json({ message: "OTP expired" });
        }

        await user.findByIdAndUpdate(otpdoc.user, { verified: true });
        await otpModel.deleteMany({ email });

        res.status(200).json({ message: "Email verified successfully" });
    } catch (error) {
        res.status(500).json({ message: "Internal server error" });
    }
};



