const express = require('express');
const router = express.Router();
const { register } = require('../controller/auth.controller');
/**
 * @route POST /api/auth/register
 */
router.post('/register', register);

module.exports = router;