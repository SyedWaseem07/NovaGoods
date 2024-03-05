import { asyncHandler } from "../utils/asyncHandler.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import { User } from "../models/user.model.js"
import bcrypt from "bcryptjs"

const registerUser = asyncHandler( async (req, res) => {
    const { username, email, password, isAdmin } = req.body;

    if(!username || !email || !password) {
        res.status(400)
        throw new Error("Please fill up all fields");
    }

    const existingUser = await User.findOne({ email })
    if(existingUser) {
        res.status(400)
        throw new Error("User all ready exists");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({ username, email, password: hashedPassword, isAdmin });

    if(!user) {
        res.status(500)
        throw new Error("Unable to register user");
    }

    return res.status(201).json(new ApiResponse(200, { username, email, isAdmin }, "User registered successfully"))

} )


const generateAccessAndRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId);

        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
        
        user.refreshToken = refreshToken;
        await user.save();

        return { accessToken, refreshToken }
    } catch (error) {
        res.status(500)
        throw new Error("Somthing went wrong while generating tokens")
    }
}

const loginUser = asyncHandler( async (req, res) => {
    const { email, password } = req.body;

    if(!email || !password) {
        res.status(400)
        throw new Error("Please fill up all fields")
    }

    const existingUser = await User.findOne({ email });

    if(!existingUser) {
        res.status(400)
        throw new Error("User not found");  
    }

    const isPasswordCorrect = await bcrypt.compare(password, existingUser?.password);
    if(!isPasswordCorrect) {
        res.status(400)
        throw new Error("Incorrect Password");
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshToken(existingUser?._id)

    return res.status(200)
    .cookie("accessToken", accessToken, { httpOnly: true, secure: true, maxAge: 24 * 60 * 60 * 1000 })
    .cookie("refreshToken", refreshToken, { httpOnly: true, secure: true, maxAge: 10 * 24 * 60 * 60 * 1000 })
    .json(new ApiResponse(200, {
        username: existingUser.username,
        email: existingUser.email,
        isAdmin: existingUser.isAdmin,
    }, "User Logged in successfully"))

} )

const logoutUser = asyncHandler ( async(req, res) => {
    await User.findByIdAndUpdate(
        req.user?._id,
        {
            $unset: {
                refreshToken: 1
            }
        }
    )

    return res.status(200)
    .clearCookie("accessToken",  { httpOnly: true, secure: true, maxAge: 0})
    .clearCookie("refreshToken",  { httpOnly: true, secure: true, maxAge: 0})
    .json(new ApiResponse(200, {}, "User logged out successfully"));
} )

const getAllUsers = asyncHandler( async (req, res) => {
    const allUsers = await User.find().select("-password -refreshToken")
    return res.status(200).json(new ApiResponse(200, allUsers, "All users fetched successfully"));
} )

const getCurrentUser = asyncHandler( async (req, res) => {
    return res.status(200).json(new ApiResponse(200, req?.user, "Current user details fetched successfully"));
} )

const updateUserProfile = asyncHandler( async (req, res) => {

    let hashedPassword;
    if(req.body?.password) 
        hashedPassword = await bcrypt.hash(req.body.password, 10);

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                username: req.body?.username || req.user?.username, 
                email: req.body?.email || req.user?.email, 
                password: hashedPassword || req.user?.password, 
            }
        },
        { new: true }
    )

    if(!user) {
        res.status(500)
        throw new Error("Unable to update user")
    }

    return res.status(200).json(new ApiResponse(200, user, "User details updated successfully"));
} )

const getUserById = asyncHandler( async (req, res) => {
    const userId = req.params.id;
    const user = await User.findById(userId).select("-password");

    if(!user) {
        res.status(400)
        throw new Error("User not found");
    }

    return res.status(200).json(new ApiResponse(200, user, "User fetched successfully"));
})

const deleteUserById = asyncHandler( async (req, res) => {
    const userId = req.params.id;
    
    const user = await User.findById(userId);
    if(!user) {
        res.status(400)
        throw new Error("User not found");
    }

    if(user.isAdmin) {
        res.status(400)
        throw new Error("Admin cannot be deleted");
    }

    const deletedUser = await User.deleteOne({ _id: userId });

    return res.status(200).json(new ApiResponse(200, {}, "User deleted successfully"));
})

const updateUserById = asyncHandler( async (req, res) => {
    const userId = req.params.id
    const user = await User.findById(userId).select("-password");
    if(!user) {
        res.status(400)
        throw new Error("User not found")
    }
    user.username = req.body?.username || user.username
    user.email = req.body?.email || user.email
    user.isAdmin = req.body?.isAdmin || user.isAdmin

    await user.save();

    const updatedUser = await User.findById(userId).select("-password");

    return res.status(200).json(new ApiResponse(200, updatedUser, "User updated successfully"));
} )
export {
    registerUser,
    loginUser,
    logoutUser,
    getAllUsers,
    getCurrentUser,
    updateUserProfile,
    getUserById,
    deleteUserById,
    updateUserById
}
