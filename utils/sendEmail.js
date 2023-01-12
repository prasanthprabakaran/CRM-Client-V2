import { createTransport } from "nodemailer";

const sendEmail = (options) =>{
    const transporter = createTransport({
        host:"smtp.gmail.com",
        port:465,
        secure:true,
        auth: {
            user:process.env.EMAIL_USERNAME,
            pass:process.env.EMAIL_PASSWORD,
        }, 
    });

    const mailOptions = {
        from: process.env.EMAIL_USERNAME,
        to: options.to,
        subject: options.subject,
        html: options.text,
    };

    transporter.sendMail(mailOptions, (err, info) => {
        if(err) {
            console.log(err);
        } else {
            console.log(info);
        }
    });
};

export default sendEmail;