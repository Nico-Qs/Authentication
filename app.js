require('dotenv').config(); // Para leer las variables de entorno y poder usarlas en el código
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
const encrypt = require("mongoose-encryption"); // Para encriptar los datos

const app = express();

console.log("API:", process.env.API_KEY);

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({
	extended: true
	}
));
app.use(express.static("public"));

mongoose.set('strictQuery', false); // Para evitar el error de que no se puede actualizar un documento que no existe
// Conectarse a la base de datos especificada
main().catch(err => console.log(err));
async function main() {
	await mongoose.connect("mongodb://0.0.0.0:27017/userDB");
}

const userSchema = new mongoose.Schema ({
	email: String,
	password: String
});

// Para encriptar el campo password
userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model("User", userSchema);

app.get("/", function(req, res) {
	res.render("home");
});

app.get("/login", function(req, res) {
	res.render("login");
});

app.get("/register", function(req, res) {
	res.render("register");
});

app.post("/register", function(req, res) {
	const newUser = new User ({
		email: req.body.username,
		password: req.body.password
	});
	newUser.save(function(err) {
		if (!err) {
			res.render("secrets");
		} else {
			console.log(err);
		}
	});
});

app.post("/login", function(req, res) {
	const username = req.body.username;
	const password = req.body.password;
	User.findOne({email: username}, function(err, foundUser){
		if (!err){
			if (foundUser && foundUser.password === password){
				res.render("secrets");
			}
			else {
				console.log("No user found or password incorrect");
			}
		}
		else {
			console.log(err);
		}
	});
})


app.listen(3000, function() {
	console.log("Server started on port 3000");
});