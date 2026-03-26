const express = require('express');
const router = express.Router();
const { register,getme,refreshToken,logout,login,logoutAll } = require('../controller/auth.controller');
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
/**
 * @route POST /api/auth/login
 */
router.post('/login', login);
/**
 * @route POST /api/auth/logout
 */
router.post('/logout', logout);
/**
 * @route POST /api/auth/logoutAll
 */
router.post('/logoutAll', logoutAll);

module.exports = router;