import bodyParser from "body-parser";
import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
const app = express()

const db =new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "Authentication",
    password: "Lakshman@123",
    port: 5432,
})

db.connect()
app.use(session({
    secret : "Topsecret",
    resave:false,
    saveUninitialized:true,
    cookie : {
        maxAge: 1000*60*60*24
    }
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(bodyParser.urlencoded({extended:true}));
app.get("/",(req,res)=>{
    res.render("signup.ejs");
})
app.post("/signup",async(req,res)=>{
    console.log(req.body)
    try{
        const result =await db.query("select * from users where email = $1; ",[req.body.username]);
        if(result.rows.length>0){
            res.redirect("/login")
            res.send("email already exists.")
        }else{
            const password = req.body.password
            bcrypt.hash(password,10,async(err,hash)=>{
                db.query("insert into users(email,password) values ($1,$2);",[req.body.username,hash])
            })
            res.render("welcome.ejs");
        }
    }catch(err){
        console.log("No Error ")
    }

    
});

app.get("/login",(req,res)=>{
    res.render("login.ejs")
})

app.get("/welcome",(req,res)=>{
    if(req.isAuthenticated()){
      res.render("welcome.ejs")
    }else{
      res.redirect("/login")
    }
})
  
app.post("/login",passport.authenticate("local",{
    successRedirect : "/welcome",
    failureRedirect: "/login"
}))

passport.use(new Strategy(async function verify(username,password,cb){
    try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
        // console.log(result.rows)
        if (result.rows.length > 0) {
          const user = result.rows[0];
          const storedPassword = user.password;
          bcrypt.compare(password,storedPassword,(err,resultu)=>{
            if(err){
                console.log("Error while comparing passwords")
            }else{
               if(resultu){
                    // res.render("welcome.ejs",{user :username});
                    return cb(null,user)
                }else{
                    // res.send("username or password is wrong")
                    return cb(null,false)
                } 
            }
            
          });
        } else {
            return cb("user not found") 
        //   res.send("User not found");
        }
      } catch (err) {
        console.log(err);
    }
}))

passport.serializeUser((user,cb)=>{
    cb(null,user)
})
passport.deserializeUser((user,cb)=>{
    cb(null,user)
})

app.listen("3000",()=>{
    console.log("http://localhost:3000");








































// app.post("/login",async(req,res)=>{
//     const email = req.body.username;
//     const password = req.body.password;
//     try {
//         const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
//         // console.log(result.rows)
//         if (result.rows.length > 0) {
//           const user = result.rows[0];
//           const storedPassword = user.password;
//           bcrypt.compare(password,storedPassword,(err,resultu)=>{
//             if(err){
//                 console.log("Error while comparing passwords")
//             }
//             if(resultu){
//                 res.render("welcome.ejs",{user :email});
//             }else{
//                 res.send("username or password is wrong")
//             }
//           })
//         } else {
//           res.send("User not found");
//         }
//       } catch (err) {
//         console.log(err);
//       }
// })
})