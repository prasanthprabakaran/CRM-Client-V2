import User from '../models/User.js'
import ErrorResponse from '../utils/errorResponse.js';
import sendEmail from '../utils/sendEmail.js'
import crypto from 'crypto';

// Registerd user
export async function register(req,res,next){
    const {username, firstname,lastname,email,password} = req.body;

    try {
        const user = await User.create({
            username, firstname, lastname, email, password
        });

        sendToken(user, 200, res);
    } catch (error) {
        next(error);
    }
}

// Login user
export async function login(req,res,next){
    const {email, password} =req.body;

    //Check if email and password is provided
    if (!email || !password) {
        return next(new ErrorResponse("Please provide an email and password",400));
    }

    try {
        // Check that user exists by email
        const user = await User.findOne({ email }).select("+password");

        if(!user){
            return next(new ErrorResponse("Invalid credentials",404));
        }

        // Check that password match
        const isMatch = await user.matchPassword(password);

        if (!isMatch) {
            return next(new ErrorResponse("Invalid credentials",401));
        }

        sendToken(user, 200, res)
    } catch (error) {
        next(error);
    }
}

// Forgot Password Initialization
export async function forgotpassword(req,res,next){
 // Send Email to email provided but first check if user exists
 const { email } =req.body;
 try {
    const user = await User.findOne({email});

    if (!user) {
        return next(new ErrorResponse("No email could not be sent", 404));
    }

    // Reset Token Gen and add to database hashed (private) version of token

    const resetToken = user.getResetPasswordToken();

    await user.save();

    // Create reset url to email to provide email
    const resetUrl = `https://crm-app-prasanth/resetpassword/${resetToken}`;

    // HTML Message 
    const message =`
        <h1>You have requested a password reset</h1>
        <a href=${resetUrl} clicktracking=off>${resetUrl}</a>
    `;

    try {
        await sendEmail({
            to: user.email,
            subject: "Password Reset Request",
            text: message,
        });

        res.status(200).json({ success: true, data: "Email Sent"});
    } catch (error) {
        console.log(error);

        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;

        await user.save();

        return next(new ErrorResponse("Email could not be sent",500));
    }
 } catch (error) {
    next(error);
 }
};

// Reset user password
export async function resetpassword(req,res,next){
    // Compare token in URL params to hashed token
    const resetPasswordToken = crypto
    .createHash("sha256")
    .update(req.params.resetToken)
    .digest("hex");

    try {
        const user = await User.findOne({
            resetPasswordToken,
            resetPasswordExpire: {$gt: Date.now() },
        });

        if (!user) {
            return next(new ErrorResponse("Invalid Token",400));
        }

        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;

        await user.save();

        res.status(201).json({
            sucess: true,
            data: "Password Updated Success",
            token: user.getSignedJwtToken(),
        });

    } catch (error) {
        next(error);
    }
};

const sendToken = (user, statusCode, res) => {
    const token = user.getSignedJwtToken();
    res.status(statusCode).json({ success: true, token })
};
