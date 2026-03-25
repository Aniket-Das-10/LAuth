const express = require('express');
const router = express.Router();
const { register,getme,refreshToken,logout } = require('../controller/auth.controller');
/**
 * @route POST /api/auth/register
 */
router.post('/register', register);
/**
 * @route GET /api/auth/getme       
 */
router.get('/getme', getme);    
/**
 * @route GET /api/auth/refresh
 */
router.get('/refresh',refreshToken);

router.get('/logout',logout);

module.exports = router;