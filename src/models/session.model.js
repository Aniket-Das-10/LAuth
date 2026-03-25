const mongoose = require('mongoose');
const { use } = require('react');

const sessionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    refreshTokenHash: {
        type: String,
        required: true
    },
    ip: {
        type: String,
        required: true 
    },
    useerAgent: {
        type: String,
        required: true
    },
    revoked: {
        type: Boolean,
        default: false 
    },
    

}, { timestamps: true });

module.exports = mongoose.model('Session', sessionSchema);