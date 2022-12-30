import * as dotenv from "dotenv";
dotenv.config();
import express from "express";
const app = express();
import cors from "cors";
import mongoose from "mongoose";
import connectDB from "./config/db.js";
import { userRouter } from './routes/userRoutes.js';
// import corsOptions from "./config/corsOptions.js";
import cookieParser from "cookie-parser";
import path from 'path';
import { fileURLToPath } from 'url';
import { logger,logEvents } from "./middleware/logger.js";
import errorHandler from "./middleware/errorHandler.js";
import { tasksRouter } from "./routes/taskRoutes.js";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
import { authRouter } from "./routes/authRoutes.js";
import { rootRouter } from "./routes/rootRouter.js";
const PORT = process.env.PORT || 3002;

connectDB();

app.use(logger);

app.use(cors({
    origin: process.env.ORIGIN,
    credentials: true,
    optionsSuccessStatus: 200
}));

app.use(express.json());

app.use(cookieParser())

app.use('/', express.static(path.join(__dirname, 'public')))
app.use("/", rootRouter);
app.use("/auth",authRouter);
app.use("/users",userRouter);
app.use('/tasks',tasksRouter);

app.all('*',(req,res)=>{
    res.status(404)
    if(req.accepts('html')){
        res.sendFile(path.join(__dirname,'views','404.html'))
    } else if (req.accepts('json')){
        res.json({message:'404 Not Found'})
    } else {
        res.type('txt').send('404 Not Found')
    }
})

app.use(errorHandler);

mongoose.connection.once('open',()=> {
    console.log('Connected to mongoDB');
    app.listen(PORT, () => console.log("Server is running on:", PORT));
})

mongoose.connection.on('error',err => {
    console.log(err);
    logEvents(`${err.no}: ${err.code}\t${err.syscall}\t${err.hostname}`, 'mongoErrLog.log');
})

