import allowedOrigins from "./allowedOrigins.js";

const corsOptions = {
    origin: (origin, callback) => {
        if(allowedOrigins.indexOf(req.header('Origin')) !== -1) {
            callback(null,true)
        } else {
            callback(new Error('Not allowed by CORS'))
        }
    },
    credentials: true,
    optionSuccessStatus: 200,
    preflightContinue: true
    // methods: ['GET','POST','PATCH','DELETE'],
    // allowedHeaders: ['Content-Type','Authorization'],
};

export default corsOptions;