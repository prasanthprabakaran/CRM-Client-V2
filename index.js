import express from "express";
import dotenv from "dotenv";
import cors from 'cors';
import connectDB from './config/db.js'
import errorHandler from './middleware/error.js' 
import {listRouter} from './routes/auth.js'
import {privateRouter} from './routes/private.js'


dotenv.config();
connectDB();

const app = express();
const PORT = process.env.PORT;
app.use(cors());
app.use(express.json());

app.get('/',(req,res,next) => {
    res.send("Api running");
})

// Connecting Routes
app.use('/api/V2/auth', listRouter);
app.use('/api/V2/private', privateRouter);
// Error handler Middleware
app.use(errorHandler);

const server = app.listen(PORT, ()=>
console.log(`server running on port ${PORT}`)
);

process.on('unhandledRejection', (err, promise)=> {
    console.log(`logged Error: ${err.message}`);
    server.close(() => process.exit(1));
})