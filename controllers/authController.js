import User from "../models/User.js";
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import sendEmail from "../utils/sendEmail.js";

// @desc Login
// @route POST /auth
// @access Public
export const login = async (req, res) => {
    const { username, password } = req.body

    if (!username || !password) {
        return res.status(400).json({ message: 'All fields are required' })
    }

    const foundUser = await User.findOne({ username }).select("+password").exec()

    if (!foundUser || !foundUser.active) {
        return res.status(401).json({ message: 'Unauthorized' })
    }

    const match = await foundUser.matchPassword(password);

    if (!match) return res.status(401).json({ message: 'Unauthorized' })

    const accessToken = jwt.sign(
        {
            "UserInfo": {
                "username": foundUser.username,
                "roles": foundUser.roles
            }
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '15m' }
    )

    const refreshToken = jwt.sign(
        { "username": foundUser.username },
        process.env.REFRESH_TOKEN_SECRET,
        { expiresIn: '7d' }
    )

    // Create secure cookie with refresh token 
    res.cookie('jwt', refreshToken, {
        httpOnly: true, //accessible only by web server 
        secure: true, //https
        sameSite: 'None', //cross-site cookie 
        maxAge: 7 * 24 * 60 * 60 * 1000 //cookie expiry: set to match rT
    })

    // Send accessToken containing username and roles 
    res.json({ accessToken })
}
// @desc Refresh
// @route GET /auth/refresh
// @access Public - because access token has expired
export const refresh = (req, res) => {
    const cookies = req.cookies

    if (!cookies?.jwt) return res.status(401).json({ message: 'Unauthorized-NoCookie' })

    const refreshToken = cookies.jwt

    jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        async (err, decoded) => {
            if (err) return res.status(403).json({ message: 'Forbidden' })

            const foundUser = await User.findOne({ username: decoded.username }).exec()

            if (!foundUser) return res.status(401).json({ message: 'Unauthorized-NoUser-Found' })

            const accessToken = jwt.sign(
                {
                    "UserInfo": {
                        "username": foundUser.username,
                        "roles": foundUser.roles
                    }
                },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: '15m' }
            )
            res.json({ accessToken })
        }
    )
}

// @desc Logout
// @route POST /auth/logout
// @access Public - just to clear cookie if exists
export const logout = (req, res) => {
    const cookies = req.cookies
    if (!cookies?.jwt) return res.sendStatus(204) //No content
    res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true })
    res.json({ message: 'Cookie cleared' })
}

export const forgetpassword = (req,res) => {
    
    const {email} =req.body;

    const user = User.findOne({email: email});

    if(!user) {
        return res.status(404).send({ 
            message: "No email could be send",
            success: false,
        });
    }

    let resetToken = () => {
        const rstToken = crypto.randomBytes(20).toString("hex");
    
        //Hash token (private key) & save to database
        user.resetPasswordToken = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");
    
        //set token expire data
        user.resetPasswordExpire = Date.now() + 10 * (60 * 1000); // 10 mins
    
        return rstToken;
    }

    user.save();

    const resetUrl = `${process.env.ORIGIN}/resetpassword/${resetToken}`;

    const message = `
    <h1>You have requested a password reset</h1>
    <p>You're almost there!</p><br><p>Click the link below to verify your email</p>
    <a href=${resetUrl} clicktracking=off> Verify your email</a>
    `;
    try{
        sendEmail({
            to: user.email,
            subject: "Password Reset Request",
            text: message,
        });
        res.status(200).json({ success: true, data: "Email Sent"});
    } catch (error) {
        console.log(error);

        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;

        user.save();

        return res.status(500).send({
            message: "Email could not be sent",
            success: false
        })
    }
    
    // const transporter = nodemailer.createTransport({
    //     service: process.env.EMAIL_SERVICE,
    //     auth: {
    //       user: process.env.EMAIL_USERNAME,
    //       pass: process.env.EMAIL_PASSWORD,
    //     },
    //     tls: {
    //       rejectUnauthorized: false,
    //     },
    //   });
    
    //   crypto.randomBytes(32, (err, buffer) => {
    //     if (err) {
    //       console.log(err);
    //     }
    //     const token = buffer.toString('hex');
    //     User.findOne({ email: email }).then((user) => {
    //       if (!user) {
    //         return res
    //           .status(422)
    //           .json({ error: 'User does not exist in our database' });
    //       }
    //       user.resetPasswordToken = token;
    //       user.resetPasswordExpire = Date.now() + 3600000;
    //       user
    //         .save()
    //         .then((result) => {
    //           transporter.sendMail({
    //             to: user.email,
    //             from: process.env.EMAIL_FROM,
    //             subject: 'Password reset request',
    //             html: `
    //                     <p>You requested for password reset from Arc Invoicing application</p>
    //                     <h5>Please click this <a href="${process.env.ORIGIN}/reset/${token}">link</a> to reset your password</h5>
    //                     <p>Link not clickable?, copy and paste the following url in your address bar.</p>
    //                     <p>${process.env.ORIGIN}/reset/${token}</p>
    //                     <P>If this was a mistake, just ignore this email and nothing will happen.</P>
    //                     `,
    //           });
    //           res.json({ message: 'check your email' });
    //         })
    //         .catch((err) => console.log(err));
    //     });
    //   });
}

export const resetpassword = async (req,res) => {
    
    const resetPasswordToken = crypto
    .createHash("sha256")
    .update(req.params.resetToken)
    .digest("hex");

    const user = await User.findOne({
        resetPasswordToken,
        resetPasswordExpire: {$gt: Date.now()},
    });

    if (!user) {
        return res.status(400).send({
            message: "Invalid Token",
            success: false,
        })
    }

    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save(); 

    const accessToken = jwt.sign(
        {
            "UserInfo": {
                "username": user.username,
                "roles": user.roles
            }
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: '15m' }
    )
    res.json({ 
        accessToken,
        success: true,
        data: "Password Updated Successfully"
    })

}

const authController = { login, refresh, logout, forgetpassword, resetpassword }

export default authController
