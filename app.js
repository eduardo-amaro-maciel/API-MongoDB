require('dotenv').config()
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS
const dbURL = `mongodb+srv://${dbUser}:${dbPass}@cluster0.viiq9oo.mongodb.net/?retryWrites=true&w=majority`

const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const express = require('express')
const app = express()

app.use(express.json())

const User = require('./models/User')

app.get('/', (req, res)  => {
    res.status(200).json({
        "msg": "Bem vindo"
    })
})


// rota privada
app.get('/user/:id', checkToken, async (req, res) => {

    const id = req.params.id
    const user = await User.findById(id, '-password')

    if (!user) { return res.status(404).json({ msg: 'Usuario não encontrado' }) }

    res.status(200).json({ user })
})


function checkToken(req, res, next) {

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token)  { return res.status(401).json({ msg: 'Acesso negado' }) }

    try {
        const secret = process.env.SECRET
        jwt.verify(token, secret)
        next()

    } catch (err) {
        res.status(400).json({ msg: 'O token é invalido' })
    }
}


app.post('/auth/register', async (req, res) => {

    const { name, email, password, confirmpassword } = req.body

    if (!name) { return res.status(422).json({ msg: 'O nome é obrigatorio' }) }

    if (!email) { return res.status(422).json({ msg: 'O email é obrigatorio' }) }

    if (!password) { return res.status(422).json({ msg: 'A senha é obrigatorio' }) }

    if (password !== confirmpassword) { return res.status(422).json({ msg: 'As senhas não conferem' }) }

    const userExists = await User.findOne({ email: email })

    if (userExists) { return res.status(422).json({ msg: 'Por favor utilize outro e-mail' }) }

    // criando a senha mais forte
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try {
        await user.save()
        res.status(201).json({ msg: 'usuario criado com sucesso' })

    } catch (err) {
        res.status(500).json({ msg: err }) 
    }
})


app.post('/auth/login', async (req, res) => {

    const { email, password } = req.body
    const user = await User.findOne({ email: email })
    const checkPassword = await bcrypt.compare(password, user.password)

    if (!email) { return res.status(422).json({ msg: 'O email é obrigatorio' }) }

    if (!password) { return res.status(422).json({ msg: 'A senha é obrigatorio' }) }

    if (!user) { return res.status(422).json({ msg: 'Usuario não encontrao' }) }

    if (!checkPassword) { return res.status(422).json({ msg: 'Usuario não encontrao' }) }

    try { 
        const secret = process.env.SECRET
        const token = jwt.sign({ id: user._id }, secret )
        res.status(200).json({ msg: 'Autenticação ok', token })

    } catch (err) {
        res.status(500).json({ msg: err }) 
    }
})

mongoose.connect(dbURL)
    .then(() => {
        console.log('conectou')
    })
    .catch((err) => {
        console.log(err)
    })

app.listen(3000)