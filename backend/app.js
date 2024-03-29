import express, { urlencoded } from "express";
import cookieParser from "cookie-parser";
import cors from "cors"
import userRouter from "./routes/user.routes.js"

const app = express();

app.use(cors({
    origin: true,
    credentails: true
}));

app.use(cookieParser());

app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public/temp"));

app.use("/api/v1/users", userRouter);
export { app }