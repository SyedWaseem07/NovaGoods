import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken"
import { User } from "../models/user.model.js";


const verifyJWT = asyncHandler( async(req, res, next) => {
    try {
        const token = req.cookies?.accessToken ||  req.header("Authorization")?.replace("Bearer ", "");
    
        if(!token) {
            res.status(400)
            throw new Error("Unauthorized request");
        }

        const decodedInfo = await jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    
        if(!decodedInfo) {
            res.status(400)
            throw new Error("Unauthorized request");
        }
    
        const user = await User.findById(decodedInfo._id);
    
        if(!user) {
            res.status(500)
            throw new Error("Unable to logout");
        }
        req.user = user;
        next();
    } catch (error) {
        throw new Error(error.message || "invalid access token");
    }
} )

export { verifyJWT }