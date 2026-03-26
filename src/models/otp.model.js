const mongoose = require('mongoose');

const otpSchema = new mongoose.Schema({
    email: { type: String, required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    hashotp: { type: String, required: true },
    expiresAt: { type: Date, required: true },
}, { timestamps: true });

exports.otpModel = mongoose.model('OtpModel', otpSchema);