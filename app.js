require('dotenv').config(); // Para leer las variables de entorno y poder usarlas en el código
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
var GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
	extended: true
	}
));
app.use(express.static("public"));

// Configuración de la sesión
app.use(session({
	secret: 'keyboard cat',
	resave: false,
	saveUninitialized: false
}));

// Inicializar passport
app.use(passport.initialize());
// Usar passport para manejar las sesiones
app.use(passport.session());

mongoose.set('strictQuery', false); // Para evitar el error de que no se puede actualizar un documento que no existe
// Conectarse a la base de datos especificada
main().catch(err => console.log(err));
async function main() {
	await mongoose.connect("mongodb://0.0.0.0:27017/userDB");
}

const userSchema = new mongoose.Schema ({
	email: String,
	password: String,
	googleId: String,
	secret: String
});

userSchema.plugin(passportLocalMongoose); // Para usar hash y salt para encriptar la contraseña y guardarla en la base de datos
userSchema.plugin(findOrCreate); // Para usar el método findOrCreate


const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
	process.nextTick(function() {
		cb(null, { id: user.id, username: user.username, name: user.name });
	});
});

passport.deserializeUser(function(user, cb) {
	process.nextTick(function() {
		return cb(null, user);
	});
});


passport.use(new GoogleStrategy({
		clientID: process.env.CLIENT_ID,
		clientSecret: process.env.CLIENT_SECRET,
		callbackURL: "http://localhost:3000/auth/google/secrets",
		userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
	},
	function(accessToken, refreshToken, profile, cb) {
		console.log(profile);
		User.findOrCreate({ googleId: profile.id }, function (err, user) {
			return cb(err, user);
		});
	}
));

app.get("/", function(req, res) {
	res.render("home");
});

app.get("/auth/google", 
	passport.authenticate('google', { scope: ['profile'] }));

	app.get("/auth/google/secrets", 
	passport.authenticate('google', { failureRedirect: '/login' }),
	function(req, res) {
		// Successful authentication, redirect home.
		res.redirect("/secrets");
	});


app.get("/login", function(req, res) {
	res.render("login");
});

app.get("/register", function(req, res) {
	res.render("register");
});

app.get("/secrets", function(req, res) {
	User.find({"secret": {$ne: null}}, function(err, foundUsers){
		if (!err){
			if (foundUsers){
				res.render("secrets", {usersWithSecrets: foundUsers});
			}
		}
	});
});

app.get("/submit", function(req, res) {
	if (req.isAuthenticated()){
		res.render("submit");
	}
	else {
		res.redirect("/login");
	}
});

app.get("/logout", function(req, res){
	req.logout(function(err){
		if (err){
			console.log(err);
		} else {
			res.redirect("/");
		}
	});
});

app.post("/register", function(req, res) {
	User.register({username:req.body.username}, req.body.password, function(err, user) {
		if (!err){
			passport.authenticate("local")(req, res, function(){
				res.redirect("/secrets");
			});
		} else {
			console.log(err);
			res.redirect("/register");
		}
	});
});

app.post("/login", function(req, res) {
	// Verificar si el usuario existe
	User.findOne({username: req.body.username}, function(err, foundUser){
		if (foundUser){
			const user = new User({
				username: req.body.username,
				password: req.body.password
			}); // Para usar el método de passport
			passport.authenticate("local", function(err, user){
				if (err){
					console.log(err);
				} else {
					// Si las credenciales son correctas, iniciar sesión
					if (user) {
						req.login(user, function(err){
							res.redirect("/secrets");
						});
					} else {
						// Si las credenciales son incorrectas, redirigir a la página de login
						res.redirect("/login");
					}
				}
			})(req, res);
		} else {
			// Si el usuario no existe, redirigir a la página de login
			res.redirect("/login");
		}
	});
});

app.post("/submit", function(req, res){
	const submittedSecret = req.body.secret;

	User.findById(req.user.id, function(err, foundUser){
		if (!err){
			if (foundUser){
				foundUser.secret = submittedSecret;
				foundUser.save(function(){
					res.redirect("/secrets");
				});
			}
		}
		else {
			console.log(err);
		}
	});
});


app.listen(3000, function() {
	console.log("Server started on port 3000");
});


/* 

Not important----------------------------------------------
Register 
bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
		const newUser = new User ({
			email: req.body.username,
			password: hash
		});
		newUser.save(function(err) {
			if (!err) {
				res.render("secrets");
			} else {
				console.log(err);
			}
		});
	});

Login
	const username = req.body.username;
	const password = req.body.password;
	User.findOne({email: username}, function(err, foundUser){
		if (!err){
			if (foundUser){
				bcrypt.compare(password, foundUser.password, function(err, result) {
					if (result){
						res.render("secrets");
					}
					else {
						console.log("Password incorrect");
					}
				});
			}
			else {
				console.log("User not found");
			}
		}
		else {
			console.log(err);
		}
	});
//const encrypt = require("mongoose-encryption"); // Para encriptar los datos
//const md5 = require("md5"); // Para encriptar los datos con MD5 mediante Hashing
//const bcrypt = require("bcrypt") // Para agregar mayor seguridad a la clave mediante salting
//const saltRounds = 10; // Número de veces que se va a aplicar el salting

// Para encriptar el campo password
//userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});
*/