var express = require("express");
var router = express.Router();

var bcrypt = require("bcryptjs");
var salt = bcrypt.genSaltSync(12);

var fabricaDeConexao = require("../../config/connection-factory");
var conexao = fabricaDeConexao();

var UsuarioDAL = require("../models/UsuarioDAL");
var usuarioDAL = new UsuarioDAL(conexao);

var { verificarUsuAutenticado, limparSessao, gravarUsuAutenticado, verificarUsuAutorizado } = require("../models/autenticador_middleware");

const {body, validationResult } = require("express-validator");

router.get("/", verificarUsuAutenticado, function (req, res){
    res.render("pages/home", req.session.autenticado, {retorno: null, erros: null, })
});

router.get("/cadastro", function(req, res){
    res.render("pages/cadastro", {listaErros, valores: {"t-nome":"","t-email":"", "t-senha":"","t-confsenha":""}})}
);


router.get("/home", function(req, res){
    res.render("pages/home", {retorno: null, erros: null})}
);

router.get("/sair", limparSessao, function(req,res){
    res.redirect("/");
})

router.get("/login", function(req, res){
    res.render("pages/login", {retorno: null, erros: null,  valores: {"t-senha":"","t-email":""}})}
);

router.get("/produto", function(req, res){
    res.render("pages/produto", {retorno: null, erros: null})}
);

router.get("/usuario", function(req, res){
    res.render("pages/usuario", {retorno: null, erros: null})}
);

router.get("/notifi", function(req, res){
    res.render("pages/notifi", {retorno: null, erros: null})}
);

router.get("/compras", function(req, res){
    res.render("pages/compras", {retorno: null, erros: null})}
);

router.get("/favoritos", function(req, res){
    res.render("pages/favoritos", {retorno: null, erros: null})}
);

router.get("/config", function(req, res){
    res.render("pages/config", {retorno: null, erros: null})}
);

router.get("/adm", function(req, res){
    res.render("pages/adm", {retorno: null, erros: null})}
);

router.post("/produto", function(req, res){
    res.json(req.body)
});

router.post( 
    "/cadastro",
    body("d-cadastro"),
    body("t-nome")
        .isInt({min: 3, max: 40})
        .withMessage("O nome deve ter no minimo 3 caracteres"),
    body("t-email")
        .isEmail({min: 5, max: 50})
        .withMessage("O email deve ser válido"), 
    body("t-senha")
        .isStrongPassword()
        .withMessage("A senha deve ser válida"),
    body("t-confsenha")
        .isStrongPassword()
        .withMessage("A senha deve ser a mesma que a anterior"),

    async function (req, res){
        var dadosForm = {
            user_usuario: req.body.nome_usu,
            email_usuario: req.body.email_usu,
            senha_usuario: bcrypt.hashSync (req.body.senha_usu, salt),
            confirmar_usuario: req.body.confSenha_usu,
        };
        const erros = validationResult(req);
        if(!erros.isEmpty()) {
            return res.render("pages/cadastro", {listaErros: erros, valores: req.body})
        }
        try {
            let create = await usuarioDAL.create(dadosForm);
            res.redirect("/")
        } catch (e) {
            res.render("pages/cadastro", {listaErros: erros, valores: req.body})
        }
    });

router.get("/adm", verificarUsuAutenticado([2, 3], "pages/restrito"), function(req,res){
    res.render("pages/adm", req.session.autenticado);
});

router.post(
    "/login",
    body("d-login"),
    body("t-email")
        .isEmail({min:5, max:50})
        .withMessage("O email deve ser válido"),
    body("t-senha")
        .isStrongPassword()
        .withMessage("A senha deve ser válida"),

    gravarUsuAutenticado(usuarioDAL, bcrypt),
    function(req, res){
        const errors = validationResult(req)
        if(!errors.isEmpty()){
            console.log(errors);    
            return res.render("pages/home", {retorno: null, erros: errors, valores: req.body});
        }
        if(req.session.autenticado != null) {
            res.redirect("/");
        } else {
            res.render("pages/login", { listaErros: erros})
        }
    });

router.post("/home", function(req, res){
    res.json(req.body)
});

module.exports = router