import { createTransport } from "nodemailer";

const sendEmail = async (options) => {
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

    await transporter.sendmail(mailOptions);
};

export default sendEmail;