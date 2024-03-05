import dotenv from "dotenv"
import { app } from "./app.js"
import { connectToDb } from "./config/db.config.js"

dotenv.config()

connectToDb()
.then(() => {

    app.on("Error", () => {
        console.log("Error in communication between server and Db");
    })

    app.listen(process.env.PORT || 8000, () => {
        console.log("Server running at port", process.env.PORT);
    })
})
.catch((error) => {
    console.log("Unable to connect index.js", error.message);
})
