import User from "../models/User.js"
import crypto from 'crypto'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import sendEmail from "../utils/sendEmail.js"
import asyncHandler from '../middleware/asyncHandler.js'

// @desc Login
// @route POST /auth
// @access Public
export const login = asyncHandler(async (req, res) => {
    const { username, password } = req.body

    if (!username || !password) {
        return res.status(400).json({ message: 'All fields are required' })
    }

    const foundUser = await User.findOne({ username }).select("+password").exec()

    if (!foundUser || !foundUser.active) {
        return res.status(401).json({ message: 'Unauthorized' })
    }

    const match = await foundUser.matchPassword(password)

    if (!match) return res.status(401).json({ message: 'Unauthorized' })

    const accessToken = jwt.sign(
        { UserInfo: { username: foundUser.username, roles: foundUser.roles } },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '15m' }
    )

    const refreshToken = jwt.sign(
        { username: foundUser.username },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '7d' }
    )

    res.cookie('jwt', refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'None',
        maxAge: 7 * 24 * 60 * 60 * 1000
    })

    res.json({ accessToken })
})

// @desc Refresh
// @route GET /auth/refresh
// @access Public
export const refresh = (req, res) => {
    const cookies = req.cookies

    if (!cookies?.jwt) return res.status(401).json({ message: 'Unauthorized' })

    const refreshToken = cookies.jwt

    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        asyncHandler(async (err, decoded) => {
            if (err) return res.status(403).json({ message: 'Forbidden' })

            const foundUser = await User.findOne({ username: decoded.username }).exec()

            if (!foundUser) return res.status(401).json({ message: 'Unauthorized' })

            const accessToken = jwt.sign(
                { UserInfo: { username: foundUser.username, roles: foundUser.roles } },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: '15m' }
            )

            res.json({ accessToken })
        })
    )
}

// @desc Logout
// @route POST /auth/logout
// @access Public
export const logout = (req, res) => {
    const cookies = req.cookies
    if (!cookies?.jwt) return res.sendStatus(204)
    res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true })
    res.json({ message: 'Cookie cleared' })
}

// @desc Forgot password
// @route POST /auth/forgetpassword
// @access Public
export const forgetpassword = asyncHandler(async (req, res) => {
    const { email } = req.body

    const user = await User.findOne({ email })

    if (!user) {
        return res.status(404).json({
            message: 'No account with that email found',
            success: false
        })
    }

    const resetToken = await user.getResetPasswordToken()

    await user.save()

    const resetUrl = `${process.env.ORIGIN}/resetpassword/${resetToken}`

    const message = `
        <h1>You have requested a password reset</h1>
        <p>You're almost there!</p>
        <p>Click the link below to reset your password:</p>
        <a href=${resetUrl} clicktracking=off>Reset your password</a>
    `

    try {
        await sendEmail({
            to: user.email,
            subject: 'Password Reset Request',
            text: message
        })

        res.status(200).json({ success: true, data: 'Email Sent' })
    } catch (error) {
        user.resetPasswordToken = undefined
        user.resetPasswordExpire = undefined
        await user.save()

        res.status(500).json({
            message: 'Email could not be sent',
            success: false
        })
    }
})

// @desc Reset password
// @route PUT /auth/resetpassword/:resetToken
// @access Public
export const resetpassword = asyncHandler(async (req, res) => {
    const resetPasswordToken = crypto
        .createHash('sha256')
        .update(req.params.resetToken)
        .digest('hex')

    const user = await User.findOne({
        resetPasswordToken,
        resetPasswordExpire: { $gt: Date.now() }
    })

    if (!user) {
        return res.status(400).json({
            message: 'Invalid or expired token',
            success: false
        })
    }

    const salt = await bcrypt.genSalt(10)
    user.password = await bcrypt.hash(req.body.password, salt)
    user.resetPasswordToken = undefined
    user.resetPasswordExpire = undefined

    await user.save()

    const accessToken = jwt.sign(
        { UserInfo: { username: user.username, roles: user.roles } },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '15m' }
    )

    res.json({
        accessToken,
        success: true,
        data: 'Password Updated Successfully'
    })
})

const authController = { login, refresh, logout, forgetpassword, resetpassword }

export default authController