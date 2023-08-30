const { validationResult } = require("express-validator");

function verificarUsuAutenticado (req, res, next) {
    if (req.session.autenticado) {
        var autenticado = req.sessions.autenticado;
    } else {
        var autenticado = {autenticado: null};
    }
    req.session.autenticado = autenticado;
    next();
}

function limparSessao(req, res, next) {
    req.session.destroy();
    next()
}

function gravarUsuAutenticado(usuarioDAL, bcrypt) {
    return async (req, re, next) => {
        erros = validationResult(req)
        if (erros.isEmpty()) {
            var dadosForm = {
                email_usuario: req.body.t-email,
                senha_usuario: req.body.t-senha
            };
            var results = await usuarioDAL.findUserEmail(dadosForm);
            var total = Object.keys(results).length;
            if (total == 1) {
                if (bcrypt.copareSync(dadosForm.t-senha, results[0].t-senha)){
                    var autenticado = {
                        autenticado: results[0].nome_usu,
                        id: results[0].id_usu,
                        tipo: results[0].tipo_usu,
                    };
                }
            } else {
                var autenticado = null;
            }
        } else {
            var autenticado = null;
        }
        req.session.autenticado = autenticado;
        next()
    }
}

function verificarUsuAutorizado(tipoPermitido, destionFalha){
    return (req, res, next) => {
        if (req.session.autenticado.autenticado != null && tipoPermitido.find(function (element) { return element == req.session.autenticado.tipo }) != undefined ) {
            next();
        } else {
            res.render(destinoFalha);
        }
    };
}

module.exports = {
    verificarUsuAutenticado,
    limparSessao,
    gravarUsuAutenticado,
    verificarUsuAutorizado
}