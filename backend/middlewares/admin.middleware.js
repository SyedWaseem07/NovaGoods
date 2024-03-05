import { asyncHandler } from "../utils/asyncHandler.js";

const verifyAdmin = asyncHandler( async (req, res, next) => {
  try {
    if(req.user?.isAdmin) next()
    else throw new Error("Only admin can access")
  } catch (error) {
    throw error
  }
} )

export { verifyAdmin }