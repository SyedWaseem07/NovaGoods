import { Router } from "express"
import {
    registerUser,
    loginUser,
    logoutUser,
    getAllUsers,
    getCurrentUser,
    updateUserProfile
} from "../controllers/user.controller.js"
import { verifyJWT } from "../middlewares/auth.middleware.js"
import { verifyAdmin } from "../middlewares/admin.middleware.js"

const router = Router();

router.route("/register").post(registerUser)
router.route("/login").post(loginUser)
router.route("/logout").post(verifyJWT, logoutUser);

router.route("/getAllUsers").get(verifyJWT, verifyAdmin, getAllUsers);
router.route("/getCurrentUser").get(verifyJWT, getCurrentUser);

router.route("/updateDetails").post(verifyJWT, updateUserProfile);

export default router;