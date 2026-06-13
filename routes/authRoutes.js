import express from "express"
const router = express.Router()
import authController from '../controllers/authController.js'
import { loginLimiter } from "../middleware/loginLimiter.js"
import validate from "../middleware/validate.js"
import { loginSchema, forgetPasswordSchema, resetPasswordSchema } from "../validators/authSchemas.js"

router.route('/').post(loginLimiter, validate(loginSchema), authController.login)

router.route('/refresh').get(authController.refresh)

router.route('/logout').post(authController.logout)

router.route('/forgetpassword').post(validate(forgetPasswordSchema), authController.forgetpassword)

router.route('/resetpassword/:resetToken').put(validate(resetPasswordSchema), authController.resetpassword)

export const authRouter = router