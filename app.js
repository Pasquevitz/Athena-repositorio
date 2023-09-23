const express = require("express");
const app = express();
const port = 2022

app.use(express.static("app/public"));

app.set("view engine", "ejs");
app.set("views", "./app/views");

app.use(express.json());
app.use(express.urlencoded({extended: true}));

app.use(
    session({
        secret: "Hello node",
        resave: false,
        saveUninitialized: false
    })
)

var rotas   = require("./app/routes/router");
app.use("/", rotas);

app.listen(port, () =>{
    console.log(`O site esta online`)
});