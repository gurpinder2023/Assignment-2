
require("./utils.js");

require('dotenv').config();
const express = require('express');

const url = require('url');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");


const expireTime = 60 * 60 * 1000; //expires after 1 hour ( minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));



var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

const { ObjectId } = require('mongodb');


function isValidSession(req){
    if(req.session.authenticated){
        return true;
    }
    return false;
}

function sessionValidation(req,res,next){
    if(isValidSession(req)){
        next();
    }else{
        res.redirect('/login');
    }
}

function isAdmin(req){
    if(req.session.user_type == 'admin'){
        return true;
    }
    return false;
}


function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}



const navLinks = [
    {name: "Home", link: "/"},
    {name: "Members", link: "/members"},
    {name: "Admin", link: "/admin"},
    {name: "404", link: "/*"},
]


app.use("/", (req,res,next) =>{
    app.locals.navLinks = navLinks;
    app.locals.currentURL = url.parse(req.url).pathname;
    next();
})
app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        
        res.render("index1");
        return;

    } else {
    
        res.render("index2" , {name : req.session.name} );
    }


});









app.get("/signup", (req, res) => {

    
    res.render("signup")
})



app.get('/login', (req, res) => {
    
    res.render("login");
});





app.post('/submitUser', async (req, res) => {


    var name = req.body.name;
    if (!name) {
        res.redirect("")
    }

    var email = req.body.email;
    var password = req.body.password;
    req.session.name = name;
    var newsession = req.session;


    const schema = Joi.object(
        {
            name: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
            password: Joi.string().max(20).required()
        });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/signup");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ name: name, email: email, password: hashedPassword,user_type: "user" });
    req.session.name = name;
    req.session.email = email;
    req.session.authenticated = true;
    req.session.cookie.maxAge = expireTime;
    console.log("Inserted user");

    // var html = "successfully created user";
    res.redirect("/members");
});

app.post('/loggingin', async (req, res) => {

    var email = req.body.email;
    var password = req.body.password;
    


    const schema = Joi.string().email().required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/login");
        return;
    }

    const result = await userCollection.find({ email: email }).project({ name: 1, email: 1, password: 1,user_type: 1, _id: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        console.log("user not found");
        res.redirect("/login");
        return;
    }
    if (await bcrypt.compare(password, result[0].password)) {
        var name = result[0].name;
        console.log("correct password");
        req.session.authenticated = true;
        req.session.email = email;
        req.session.name = name;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/loggedIn');
        return;
    }
    else {
        
        res.render("loggingin");
        return;
    }
});

app.get('/loggedin', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }

    res.redirect('/members');
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    
    res.redirect('/');
});

app.get("/members", (req, res) => {
    const name = req.session.name;
    if (!req.session.authenticated) {
        res.redirect('/login');
        return;

    }
    console.log(req.session)

    
    res.render("members", {name : req.session.name});


})

app.get('/admin',  sessionValidation, adminAuthorization,async (req,res) => {
    const result = await userCollection.find().project({name: 1, _id: 1 , user_type:1}).toArray();
    console.log(result);
    res.render("admin", {users: result});
});


app.post('/admin/promote/:id', sessionValidation, adminAuthorization, async (req, res) => {
    const userId = req.params.id;
    await userCollection.updateOne({ _id: ObjectId(userId) }, { $set: { user_type: 'admin' } });
    res.redirect('/admin');

  });
  
  app.post('/admin/demote/:id', sessionValidation, adminAuthorization, async (req, res) => {
    const userId = req.params.id;
    await userCollection.updateOne({ _id: ObjectId(userId) }, { $set: { user_type: 'user' } });
    res.redirect('/admin');

  });
  




app.use(express.static(__dirname + "/public"));

app.get("*", (req, res) => {
    res.status(404);
    res.render("404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 