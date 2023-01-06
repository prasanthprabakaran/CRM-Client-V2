import mongoose from "mongoose";
import bcrypt from 'bcrypt'
import crypto from 'crypto'

const UserSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    firstname: {
        type: String,
        required: true
    },
    lastname: {type: String},
    email:{
        type: String,
        required: [true, "Please provide email address"],
        unique: true,
        match: [
            /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
            "Please provide a valid email",
          ],
    },
    password: {
        type: String,
        required: true,
        minlength: 6,
        select: false,
    },
    roles: {
        type: [String],
        default: ["Employee"]
    },
    active: {
        type: Boolean,
        default: true
    },
    resetPasswordToken: String,
    resetPasswordExpire: Date,
})

UserSchema.methods.matchPassword = async function (password) {
    return await bcrypt.compare(password, this.password)
}

UserSchema.methods.getResetPasswordToken = function () {
    const resetToken = crypto.randomBytes(20).toString("hex");

    //Hash token (private key) & save to database
    this.resetPasswordToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

    //set token expire data
    this.resetPasswordExpire = Date.now() + 10 * (60 * 1000); // 10 mins

    return resetToken;
}


const User = mongoose.model("User",UserSchema);

export default User;
