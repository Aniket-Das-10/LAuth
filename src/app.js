const express = require('express');
const morgan = require('morgan');
const authRoutes = require('./routes/auth.routes');
const cookieParser = require('cookie-parser');

const app = express();

app.use(morgan('dev'));
app.use(express.json());
app.use(cookieParser());


app.use('/api/auth', authRoutes);


module.exports = app;