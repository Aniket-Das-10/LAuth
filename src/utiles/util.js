export function generateOtp() {
    return Math.floor(100000 + Math.random() * 900000);
};

export function getOtpHtml(otp) {
    return ` <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OTP Verification</title>
        <style>
            body {
                font-family: Arial, sans-serif;
            }
        </style>
    </head>
    <body>
        <h1>Your OTP for login is ${otp}</h1>
        <p>This OTP is valid for 10 minutes</p>
    </body>
</html>`;
}