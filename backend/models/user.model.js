import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken"

const userSchema = new Schema({
    username: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    isAdmin: {
        type: Boolean,
        required: true,
        default: false
    }
})

userSchema.methods.generateAccessToken = function() {
    return jwt.sign(
        {
            _id: this._id,
        email: this.email,
        username: this.username
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: "1d"
        }
    )
}

userSchema.methods.generateRefreshToken = function() {
    return jwt.sign(
        {
            _id: this._id
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: "10d"
        }
    )
}

export const User = mongoose.model("User", userSchema);

