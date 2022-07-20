import express from 'express';
const router = express.Router();

//Controllers

import {
    login,
    register,
    forgotpassword,
    resetpassword
} from '../controllers/auth.js';

router.route('/register').post(register);

router.route('/login').post(login);

router.route('/forgotpassword').post(forgotpassword);

router.route('/resetpassword/:resetToken').put(resetpassword);

export const listRouter = router;