import mongoose from "mongoose";

const connectToDb = async () => {
    try {
        const connectionInstance = await mongoose.connect(process.env.MONGODB_URI);
        console.log("Successfully Connected to MongoDb");
    } catch (error) {
        console.error("MongoDB connection failed", error.message);
        process.exit(1);
    }
}
export { connectToDb }