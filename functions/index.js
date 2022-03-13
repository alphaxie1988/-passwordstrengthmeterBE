//** Start of Import Libaries **//
const functions = require("firebase-functions");
const express = require('express');
const crypto = require("crypto");
const app = express();
var cors = require("cors");
//** End of Import Libaries **//




//** Start of  Settings **//
//Default port
const PORT = 3002;
// m is a very long number used to be encrpyted using user's password+ salt as key.
let m="9923585919153401269551650121163912027121788581518886189082113878";
// Encrpyt take in password and encrypt the m using client password
const encrypt = (passwordAskey) =>{
  const hmac = crypto.createHmac('sha256', passwordAskey)
  return hmac.update(m).digest('base64');;
}
// Salt is just a random text to appebnd to the user password to make it more random
let salt="apple";
// User name is hardcoded to smuuser
let userlogin = "smuuser";
// User public key
let publicKey = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3QAhhXP+a8K3MrJIV1iigORhw7lz/I4Ms2+KOo0QtFZYm/jpl37BSLX69e4ca+L8v/NLwM638MRqaDmCcnLVzJ957A236yy9AhByiUYJVGey9Kbh9KkPhiFAVdTCX+rI0KVrkw6lDz1YQzgd5kJZMez/IsdxQTyjWBPI1N0Ks/mlZAa6LVprLRN6G2ZG8ymTsGGcvZ4ccneRwK0FQFyuRuYu5mN8mG9L1EIlU8it5yqrIWMpxHqEO0cweVosFIkxCpHeZ6/4ZYRgmszfUG3JkrjdW1bxdqJF4ReE6Ub0sEk0hgK/oZlIhqjfWEreM3UNcaT+7Zh4PO3rdf762M/aowIDAQAB\n-----END PUBLIC KEY-----";
// Convert a given string into number this is to prevent special character in password
const convertToNumber = (e) => {for(var r=0,i=0;i<e.length;i++)r=(r<<5)-r+e.charCodeAt(i),r&=r;return r};
// Default password is (Password123 + salt)
let password =encrypt((convertToNumber("Password123")+salt).toString());
//** End of  Settings **//







//** Start of Declaring Functions **//
/* Get current time in ISO */
const getCurrentTime = (lastMin) =>{
  
    let date_ob = new Date();

    if(lastMin){
      date_ob.setMinutes( date_ob.getMinutes() - 1 );
    }
    console.log("Getting OTP using this time:" + date_ob.toISOString().substring(0,16));
    // current date
    return date_ob.toISOString().substring(0,16);
  }

/* this function take in if last min, and return a 6 digit number base on userlogin,password,time etc*/
const getOTP = (lastMin) =>
{
return (parseInt(crypto.createHash('sha256').update((userlogin+ password + getCurrentTime(lastMin))).digest('hex'),16) % 1000000).toString().padStart(6, '0')
}
//** End of  Declaring Functions **//






/* JSON body parse*/
const bodyParser = require('body-parser');
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

/* GET OTP return the OTP and encrypted it using the publickey of the user and converting it into base64. */
app.get("/getOTP", function (req, res, next) {
 

    const encryptedData = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: "sha1",
      },
      Buffer.from(getOTP(false))
    );
    res.send(encryptedData.toString("base64"));
  });

  
/* POST Login return login result */
app.post('/login', function(req, res) {
    console.log('Receiving Login Request ...');
    //This return error and logging is for troubleshooting, in production we are not suppose to send different error message
    if(req.body.username!=userlogin)
    {
      console.log('Failed Login by user:'+ req.body.username);
      console.log("req.body.username: "+ req.body.username + "\nuserlogin:"+userlogin)
      res.sendStatus(403);
      return;
    }
    if(encrypt(req.body.password.toString()+salt) != password)
    {
      console.log('Failed Login by user:'+ req.body.username);
      console.log("encrypt(req.body.password.toString()+salt): "+ encrypt(req.body.password.toString()+salt) + "\npassword:"+ password); 
      res.sendStatus(401);
      return;
    }
    if( (req.body.otp != (getOTP(false)) && req.body.otp != (getOTP(true))))
    {
      console.log('Failed Login by user:'+ req.body.username);
      console.log("req.body.otp:"+ req.body.otp);
      res.sendStatus(412);
      return;
    }
      console.log('Successful Login by user:'+ req.body.username);
      res.sendStatus(200);
    
  });

/* Take in password and change it stored the encrypted m using password + salt as key */
app.post('/changepassword', function(req, res) {
console.log('Receiving change password request ...' + "\nInt of Password:"+req.body+"\nSaved password as: "+encrypt(req.body.password.toString()+salt));
password = encrypt(req.body.password.toString()+salt)
res.sendStatus(200);
});
  

/* Application Start here */
app.listen(PORT, () => {
console.info('Server is running on PORT:', PORT);
});

exports.app = functions.https.onRequest(app);
