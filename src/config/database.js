const mongoose = require('mongoose');

async function connectDB() {
    try {
        await mongoose.connect(require('./config').MONGO_URL);
        console.log('Connected to MongoDB');
    } catch (error) {
        console.error('Error connecting to MongoDB:', error);
        process.exit(1);
    }
}

module.exports = connectDB;