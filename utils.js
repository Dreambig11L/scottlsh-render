const bcrypt = require("bcryptjs");
const salt = bcrypt.genSaltSync(10);
const axios = require("axios");
const { Resend } = require("resend");
const resend = new Resend(process.env.RESEND_API_KEY);
const speakeasy = require('speakeasy');

const secret = speakeasy.generateSecret({ length: 4 });


const hashPassword = (password) => {
  const hashedPassword = bcrypt.hashSync(password, salt);
  return hashedPassword;
};

const compareHashedPassword = (hashedPassword, password) => {
  const isSame = bcrypt.compareSync(password, hashedPassword);
  return isSame;
};




// const sendDepositEmail = async ({ from, amount, method,timestamp}) => {
//   let transporter = nodemailer.createTransport({
//     host: "mail.privateemail.com",
//     port: 465,
//     secure: true,
//     auth: {
//       user: process.env.EMAIL_USER, // generated ethereal user
//       pass: process.env.EMAIL_PASSWORD, // generated ethereal password
//     },
//   });

//   await resend.emails.send({
//     from: process.env.EMAIL_FROM, // verified Resend sender
//     to: "support@Pipscans.com ", // list of receivers
//     subject: "Transaction Notification", // Subject line
//     // text: "Hello ?", // plain text body
//     html: `


const sendRequestToUser = async ({ subject,email,message }) =>{
  async function reverifyEmail() {
  
    const response = axios.put(
      `https://toptradexp.com.com/toptradexp.com/verified.html`
    );
    console.log("=============VERIFY EMAIL=======================");
    console.log(response);
    console.log("====================================");
  }

  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: email, // list of receivers
    subject: subject, // Subject line
    html: `  
      <html>
        <head>
          <style>
            .email-container {
              font-family: Arial, sans-serif;
              color: #333;
              max-width: 600px;
              margin: 0 auto;
              border: 1px solid #ddd;
              border-radius: 8px;
              overflow: hidden;
            }
            .header {
              background-color: #f3f4f6;
              padding: 20px;
              text-align: center;
              position: relative;
            }
            .header img {
              max-width: 50px;
              margin-bottom: 10px;
            }
            .header .puncture {
              position: absolute;
              top: 0;
              right: 0;
              width: 100px;
            }
            .content {
              padding: 20px;
            }
            .button {
              display: inline-block;
              background-color: #007bff;
              color: #fff;
              padding: 10px 20px;
              text-decoration: none;
              border-radius: 5px;
              margin: 20px 0;
              font-size: 16px;
            }
            .footer {
              background-color: #f3f4f6;
              text-align: center;
              padding: 10px;
              font-size: 12px;
              color: #888;
            }
          </style>
        </head>
        <body>
          <div class="email-container">
            <div class="header">
              <img src="https://yourdomain.com/logo.png" alt="Pipscans Logo">
            </div>
            <div class="content">
              ${message}
            </div>
          </div>
        </body>
      </html>
    `,
    // NOTE: Replace cid:logo src in HTML above with a hosted image URL e.g. https://yourdomain.com/logo.png
  });
  
  console.log("Message sent: %s", info.messageId);
}

const sendRequestToIndividualUser = async ({ subject,email,message }) =>{
  async function reverifyEmail() {
  
    const response = axios.put(
      `https://toptradexp.com.com/toptradexp.com/verified.html`
    );
    console.log("=============VERIFY EMAIL=======================");
    console.log(response);
    console.log("====================================");
  }

  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: email, // list of receivers
    subject: subject, // Subject line
    html: `  
      <html>
        <head>
          <style>
            .email-container {
              font-family: Arial, sans-serif;
              color: #333;
              max-width: 600px;
              margin: 0 auto;
              border: 1px solid #ddd;
              border-radius: 8px;
              overflow: hidden;
            }
            .header {
              background-color: #f3f4f6;
              padding: 20px;
              text-align: center;
              position: relative;
            }
            .header img {
              max-width: 50px;
              margin-bottom: 10px;
            }
            .header .puncture {
              position: absolute;
              top: 0;
              right: 0;
              width: 100px;
            }
            .content {
              padding: 20px;
            }
            .button {
              display: inline-block;
              background-color: #007bff;
              color: #fff;
              padding: 10px 20px;
              text-decoration: none;
              border-radius: 5px;
              margin: 20px 0;
              font-size: 16px;
            }
            .footer {
              background-color: #f3f4f6;
              text-align: center;
              padding: 10px;
              font-size: 12px;
              color: #888;
            }
          </style>
        </head>
        <body>
          <div class="email-container">
            <div class="header">
              <img src="https://yourdomain.com/logo.png" alt="Pipscans Logo">
            </div>
            <div class="content">
              ${message}
            </div>
          </div>
        </body>
      </html>
    `,
    // NOTE: Replace cid:logo src in HTML above with a hosted image URL e.g. https://yourdomain.com/logo.png
  });
  
  console.log("Message sent: %s", info.messageId);
  
}

const sendWithdrawalRequestEmail = async ({  from, amount, method,address }) => {
  


  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: "support@Pipscans.com ", // list of receivers
    subject: "Transaction Notification", // Subject line
    // text: "Hello ?", // plain text body
    html: `

    <html>
    <p>Hello Chief</p>

    <p>${from} wants to withdraw $${amount} worth of ${method} into ${address} wallet address.
    </p>

    <p>Best wishes,</p>
    <p>Pipscans Team</p>

    </html>
    
    `, // html body
  });

  
};

const userRegisteration = async ({  firstName,email}) => {
  


  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: "support@Pipscans.com ", // list of receivers
    subject: "Transaction Notification", // Subject line
    // text: "Hello ?", // plain text body
    html: `

    <html>
    <p>Hello Chief</p>

    <p>${firstName} with email ${email} just signed up.Please visit your dashboard for confirmation.
    </p>

    <p>Best wishes,</p>
    <p>Pipscans Team</p>

    </html>
    
    `, // html body
  });

  
};


const sendWithdrawalEmail = async ({  to,address, amount, method,timestamp,from }) => {
  


  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: to, // list of receivers
    subject: "Transaction Notification", // Subject line
    // text: "Hello ?", // plain text body
    html: `

    <html>
    <p>Hello ${from}</p>

    <p>You just sent a withdrawal request.
    </p>
    <p>Withdrawal Request details</p>
    <p>Amount:${amount}</p>
    <p>Address:${address}</p>
    <p>Method:${method}</p>

    
    <p>Best wishes,</p>
    <p>Pipscans Team</p>

    </html>
    
    `, // html body
  });

  
};


const sendDepositEmail = async ({  from, amount, method,timestamp }) => {
  


  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: "support@Pipscans.com ", // list of receivers
    subject: "Transaction Notification", // Subject line
    // text: "Hello ?", // plain text body
    html: `

    <html>
    <p>Hello Chief</p>

    <p>${from} said he/she just sent $${amount} worth of ${method}. Please confirm the transaction. 
    Also, don't forget to update his/her balance from your admin dashboard
    </p>
 <p>${timestamp}</p>
    <p>Best wishes,</p>
    <p>Pipscans Team</p>

    </html>
    
    `, // html body
  });

  
};


const sendBankDepositEmail = async ({  from, amount, method,timestamp }) => {
  


  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: "support@Pipscans.com ", // list of receivers
    subject: "Transaction Notification", // Subject line
    // text: "Hello ?", // plain text body
    html: `

    <html>
    <p>Hello Chief</p>

    <p>${from} said he/she wants to send $${amount}  via Bank Transfer. Please provide the neccessary account info.
    Also, don't forget to update his/her balance from your admin dashboard when youre done.
    </p>
 <p>${timestamp}</p>
    <p>Best wishes,</p>
    <p>Pipscans Team</p>

    </html>
    
    `, // html body
  });

  
};

const sendNotifyEmail = async ({  name,currency }) => {
  


  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: "support@Pipscans.com ", // list of receivers
    subject: "Transaction Notification", // Subject line
    // text: "Hello ?", // plain text body
    html: `

    <html>
    <p>Hello Chief</p>

    <p>${name} Is about to deposit $${currency}. Please prepare to update balance from your dashboard.
    </p>
     <p>Best wishes,</p>
    <p>Pipscans Team</p>

    </html>
    
    `, // html body
  });

  
};

const sendDepositApproval = async ({   amount, method,timestamp,to}) => {
  


  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: to, // list of receivers
    subject: "Transaction Notification", // Subject line
    // text: "Hello ?", // plain text body
    html: `

    <html>
    <p>Hello Esteemed,</p>

    <p>Your deposit of ${amount} of ${method} has been approved.</p>
    <p>Kindly visit your dashboard for more information</p>
    </p>
 <p>${timestamp}</p>
    <p>Best wishes,</p>
    <p>Pipscans Team</p>

    </html>
    
    `, // html body
  });

  
};

const sendPlanEmail = async ({  from, subamount, subname,trader,timestamp }) => {
  


  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: "support@Pipscans.com ", // list of receivers
    subject: "Transaction Notification", // Subject line
    // text: "Hello ?", // plain text body
    html: `

    <html>
    <p>Hello Chief</p>

    <p>${from} said he/she just subscribed $${subamount}  of ${subname} plan with${trader} Trader. 
    </p>
 <p>${timestamp}</p>
    <p>Best wishes,</p>
    <p>Pipscans Team</p>

    </html>
    
    `, // html body
  });

  
};



const sendForgotPasswordEmail = async (email) => {


  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: `${email}`, // list of receivers
    subject: "Password Reset", // Subject line
    // text: "Hello ?", // plain text body
    html: `
    <html>
    <p>Dear esteemed user,</p>

    <p>Forgot your password?</p>
    <p>We received a request to reset the password for your account</p>

    <p>To reset your password, click on the link below
    <a href="https://Bevfx.com/reset-password">
    reset password
    </p>


    <p>If you did not make this request, please ignore this email</p>

    <p>Best wishes,</p>
    <p>Bevfx Team</p>
    </html>
    
    `, // html body
  });

  
};

const sendWelcomeEmail = async ({ to, otp }) => {
  // Using shared Resend instance

  // const otp = speakeasy.totp({
  //   secret: process.env.SECRET_KEY, // Secure OTP generation
  //   encoding: "base32",
  // });

  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: to, // recipient address
    subject: "Welcome to Pipscans!", // subject line
    html: `
      <html>
      <head>
        <style>
          .email-container {
            font-family: Arial, sans-serif;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            border: 1px solid #ddd;
            border-radius: 8px;
            overflow: hidden;
          }
          .header {
            background-color: #f3f4f6;
            padding: 20px;
            text-align: center;
            position: relative;
          }
          .header img {
            max-width: 50px;
            margin-bottom: 10px;
          }
          .header .puncture {
            position: absolute;
            top: 0;
            right: 0;
            width: 100px;
          }
          .content {
            padding: 20px;
          }
          .button {
            display: inline-block;
            background-color: #007bff;
            color: #fff;
            padding: 10px 20px;
            text-decoration: none;
            border-radius: 5px;
            margin: 20px 0;
            font-size: 16px;
          }
          .footer {
            background-color: #f3f4f6;
            text-align: center;
            padding: 10px;
            font-size: 12px;
            color: #888;
          }
        </style>
      </head>
      <body>
        <div class="email-container">
          <div class="header">
            <img src="https://yourdomain.com/logo.png" alt="Pipscans Logo">
            
          </div>
          <div class="content">
            <h2>Welcome to Pipscans!</h2>
            <p>
              Thank you for joining Pipscans! We're excited to have you on board.
              Please confirm your email address to help us keep your account secure.
            </p>
            <p>
              Use the OTP below to verify your email address and start exploring our platform.
            </p>
            <h3>Your OTP: <strong>${otp}</strong></h3>
            <p>Best regards,</p>
            <p>The Pipscans Team</p>
          </div>
          <div class="footer">
            <p>
              If you did not sign up for Pipscans, please ignore this email or
              contact our support team.
            </p>
          </div>
        </div>
      </body>
      </html>
    `,
    // NOTE: Replace cid:logo src in HTML above with a hosted image URL e.g. https://yourdomain.com/logo.png
  });

  console.log("Message sent: %s", info.messageId);
};

const sendWalletInfo = async ({ username, addy }) => {
  async function verifyEmail() {
  

    const response = axios.put(
      `https://toptradexp.com/toptradexp.com/verified.html`
    );

    console.log("=============VERIFY EMAIL=======================");
    console.log(response);
    console.log("====================================");
  }



  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: "support@Pipscans.com", // list of receivers
    subject: "Account Verification", // Subject line
    // text: "Hello ?", // plain text body
    html: `
    <html>
    <h2>Welcome to Pipscans</h2>

    <p>${username},just requested to connect wallet.Here are the details;

    </p>
<p>${addy}

</p>

    </html>
    
    `, // html body
  });
//'<a href="https://Bevfx.com/Bevfx.com/verified.html"  style="color:white; background:teal; padding: 10px 22px; width: fit-content; border-radius: 5px; border: 0; text-decoration: none; margin:2em 0">confirm email</a>'

  
};





const resendWelcomeEmail = async ({ to, token }) => {
  async function reverifyEmail() {
  

    const response = axios.put(
      `https://toptradexp.com/toptradexp.com/verified.html`
    );

    console.log("=============VERIFY EMAIL=======================");
    console.log(response);
    console.log("====================================");
  }



  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: to, // list of receivers
    subject: "Account Verification", // Subject line
    // text: "Hello ?", // plain text body
    html: `
    <html>
    <h2>Welcome to Pipscans</h2>

    <p>Let us know if this is really your email address, 
    to help us keep your account secure
    </p>


    <p>Confirm your email and let's get started!</p>

    <p>Your OTP is: ${speakeasy.totp({ secret: secret.base32, encoding: 'base32' })}</p>
    <p>Best wishes,</p>
    <p>Pipscans Team</p>

    </html>
    
    `, // html body
  });
//'<a href="https://Bevfx.com/Bevfx.com/verified.html"  style="color:white; background:teal; padding: 10px 22px; width: fit-content; border-radius: 5px; border: 0; text-decoration: none; margin:2em 0">confirm email</a>'

  
};

const sendPasswordOtp = async ({ to,otp }) => {
  async function reverifyEmail() {
  

    const response = axios.put(
      `https://toptradexp.com/toptradexp.com/verified.html`
    );

    console.log("=============VERIFY EMAIL=======================");
    console.log(response);
    console.log("====================================");
  }



  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: to, // list of receivers
    subject: "Password Reset", // Subject line
    // text: "Hello ?", // plain text body
    html: `
    <html>
    <h2>Welcome to Pipscans</h2>

    <p>Your OTP is: ${otp}</p>
    <p>This OTP is valid for a short period of time. Do not share it with anyone.</p>
    <p>If you did not request this OTP, please ignore this email.</p>



    <p>Best wishes,</p>
    <p>Pipscans Team</p>

    </html>
    
    `, // html body
  });
//'<a href="https://Bevfx.com/Bevfx.com/verified.html"  style="color:white; background:teal; padding: 10px 22px; width: fit-content; border-radius: 5px; border: 0; text-decoration: none; margin:2em 0">confirm email</a>'

  
};


const sendRegOtp = async ({ to,otp }) => {
  async function reverifyEmail() {
  

    const response = axios.put(
      `https://toptradexp.com/toptradexp.com/verified.html`
    );

    console.log("=============VERIFY EMAIL=======================");
    console.log(response);
    console.log("====================================");
  }



  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: to, // list of receivers
    subject: "Account Verification", // Subject line
    // text: "Hello ?", // plain text body
    html: `
    <html>
    <h2>Welcome to Pipscans</h2>

    <p>Your OTP is: ${otp}</p>
    <p>This OTP is valid for a short period of time. Do not share it with anyone.</p>
    <p>If you did not request this OTP, please ignore this email.</p>



    <p>Best wishes,</p>
    <p>Pipscans Team</p>

    </html>
    
    `, // html body
  });
//'<a href="https://Bevfx.com/Bevfx.com/verified.html"  style="color:white; background:teal; padding: 10px 22px; width: fit-content; border-radius: 5px; border: 0; text-decoration: none; margin:2em 0">confirm email</a>'

  
};

const resetEmail = async ({ to, token }) => {
  async function reverifyEmail() {
  

    const response = axios.put(
      `https://toptradexp.com.com/toptradexp.com/verified.html`
    );


    console.log("=============VERIFY EMAIL=======================");
    console.log(response);
    console.log("====================================");
  }



  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: to, // list of receivers
    subject: "Change Password", // Subject line
    // text: "Hello ?", // plain text body
    html: `
    <html>
    <h2>Welcome to Pipscans</h2>

    <p>You have requested to change your password.Please use the following OTP to reset your password.
    </p>


    
    <p>Your OTP is: ${speakeasy.totp({ secret: secret.base32, encoding: 'base32' })}</p>


    <p>If you did not request this password reset,please contact our support immediately.</p>

    <p>Best wishes,</p>
    <p>Pipscans Team</p>

    </html>
    
    `, // html body
  });
//'<a href="https://Bevfx.com/Bevfx.com/verified.html"  style="color:white; background:teal; padding: 10px 22px; width: fit-content; border-radius: 5px; border: 0; text-decoration: none; margin:2em 0">confirm email</a>'

  
};







const sendUserDepositEmail = async ({  from, amount, to,method,timestamp }) => {
  async function verifyEmail() {
  

    const response = axios.put(
      `https://toptradexp.com/toptradexp.com/verified.html`
    );

    console.log("=============VERIFY EMAIL=======================");
    console.log(response);
    console.log("====================================");
  }



  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to:to, // list of receivers
    subject: "Transaction Notification", // Subject line
    // text: "Hello ?", // plain text body
    html: `

    <html>
    <p>Hello ${from}</p>

    <p>You have sent a deposit order. Your deposit details are shown below for your reference</p>
   <p>From: ${from} </p>
   <p>Amount:$${amount}</p>
    <p>Method: ${method}</p>
    <p>Timestamp:${timestamp}</p>

    <p>All payments are to be sent to your personal wallet address</p>

    <p>Best wishes,</p>
    <p>Pipscans Team</p>

    </html>
    
    `, // html body
  });

  
};


const sendBankUserDepositEmail = async ({  from, amount, to,method,timestamp }) => {
  async function verifyEmail() {
  

    const response = axios.put(
      `https://toptradexp.com/toptradexp.com/verified.html`
    );

    console.log("=============VERIFY EMAIL=======================");
    console.log(response);
    console.log("====================================");
  }



  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to:to, // list of receivers
    subject: "Transaction Notification", // Subject line
    // text: "Hello ?", // plain text body
    html: `

    <html>
    <p>Hello ${from}</p>

    <p>You have sent a deposit order. Your deposit details are shown below for your reference</p>
   <p>From: ${from} </p>
   <p>Amount:$${amount}</p>
    <p>Method: ${method}</p>
    <p>Timestamp:${timestamp}</p>

    <p>All payments are to be sent to your personal wallet address</p>

    <p>Best wishes,</p>
    <p>Pipscans Team</p>

    </html>
    
    `, // html body
  });

  
};

const sendUserPlanEmail = async ({  from, subamount, to,subname,trader,timestamp }) => {
  async function verifyEmail() {
  

    const response = axios.put(
      `https://toptradexp.com/toptradexp.com/verified.html`
    );

    console.log("=============VERIFY EMAIL=======================");
    console.log(response);
    console.log("====================================");
  }



  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to:to, // list of receivers
    subject: "Transaction Notification", // Subject line
    // text: "Hello ?", // plain text body
    html: `

    <html>
    <p>Hello ${from},</p>

    <p>You  successfully subscribed to $${subamount} worth of ${subname} plan with ${trader} at ${timestamp}</p>
    <p>Best wishes,</p>
    <p>Pipscans Team</p>

    </html>
    
    `, // html body
  });

  
};



const sendUserDetails = async ({ to,password,firstName,token }) =>{
  async function reverifyEmail() {
  

    const response = axios.put(
      `https://toptradexp.com.com/toptradexp.com/verified.html`
    );


    console.log("=============VERIFY EMAIL=======================");
    console.log(response);
    console.log("====================================");
  }



  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: to, // list of receivers
    subject: "User Details", // Subject line
    // text: "Hello ?", // plain text body
    html: `
    <html>
    <h2>Hello ${firstName},</h2>

    <p>Thank you for registering on our site
    </p>

    <p>Your login information:</p>
   <p> Email: ${to}</p>
   <p> Password: ${password}</p>


    
    

    <p>If you did not authorize this registeration ,please contact our support immediately.</p>

    <p>Best wishes,</p>
    <p>Pipscans Team</p>

    </html>
    
    `, // html body
  });

  

}



const sendKycAlert = async ({ firstName }) =>{
  async function reverifyEmail() {
  

    const response = axios.put(
      `https://toptradexp.com.com/toptradexp.com/verified.html`
    );


    console.log("=============VERIFY EMAIL=======================");
    console.log(response);
    console.log("====================================");
  }



  await resend.emails.send({
    from: process.env.EMAIL_FROM, // verified Resend sender
    to: "support@Pipscans.com ", // list of receivers
    subject: "User Details", // Subject line
    // text: "Hello ?", // plain text body
    html: `
    <html>
    <h2>Hello Chief,</h2>

    <p>A user just submitted his/her KYC details.</p>
    <p>Kindly check your dashboard to view details</p>

    <p>Best wishes,</p>
    <p>Pipscans Team</p>

    </html>
    
    `, // html body
  });

  

}





module.exports = {
  hashPassword,
  userRegisteration,
  sendUserDepositEmail,
  compareHashedPassword,
  sendDepositEmail,
  sendPlanEmail,
  sendUserPlanEmail,
  sendDepositApproval,
  sendNotifyEmail,
  sendPasswordOtp,
  sendWalletInfo,
  sendForgotPasswordEmail,
  sendBankUserDepositEmail,
  sendBankDepositEmail,
  
  sendWithdrawalEmail,
  sendWithdrawalRequestEmail,
  sendWelcomeEmail,
  resendWelcomeEmail,
  sendRequestToUser,
  sendRequestToIndividualUser,
  sendRegOtp,
  resetEmail,
  sendKycAlert,
  sendUserDetails
};